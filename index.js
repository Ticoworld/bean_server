const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { generateWallet, generateSecretKey, getStxAddress, restoreWalletAccounts } = require('@stacks/wallet-sdk');
const {
  makeContractCall,
  broadcastTransaction,
  uintCV,
  standardPrincipalCV,
  noneCV,
  someCV,
  stringUtf8CV,
  FungibleConditionCode,
  createAsset,
  PostConditionMode,
  Pc,
  principalCV,
  TransactionVersion
} = require('@stacks/transactions');
const { STACKS_MAINNET } = require('@stacks/network');
const TelegramBot = require('node-telegram-bot-api');
const crypto = require('crypto');
const User = require('./model/user.model')

require('dotenv').config();
const network = STACKS_MAINNET
const PRIVATE_KEY_SECRET = process.env.PRIVATE_KEY_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const IV_LENGTH = 16;

const app = express();
const PORT = 5000;

app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });
const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN);

app.post("/webhook", (req, res) => {
  bot.processUpdate(req.body);
  res.sendStatus(200);
});

app.get("/", (req, res) => {
  res.send("Server is running");
});



function encryptPrivateKey(privateKey, pin) {
  // Derive a key by combining the PIN and the PRIVATE_KEY_SECRET
  const combinedKey = crypto.createHash('sha256').update(pin + PRIVATE_KEY_SECRET).digest();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', combinedKey, iv);
  let encrypted = cipher.update(privateKey);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

/**
 * Helper function to generate a specified number of unique random indexes.
 */
function generateUniqueIndexes(max, count) {
  const indexes = new Set();
  while (indexes.size < count) {
    indexes.add(Math.floor(Math.random() * max));
  }
  return Array.from(indexes);
}

/**
 * Generate Wallet:
 * - Creates a wallet using a random secret phrase.
 * - Returns wallet address, private key, and seed phrase.
 */
async function createWallet() {
  const secretKey = generateSecretKey(128);
  const wallet = await generateWallet({ secretKey, password: 'password' });
  const account = wallet.accounts[0];
  const address = getStxAddress({ account, transactionVersion: TransactionVersion });

  return {
    address,
    privateKey: account.stxPrivateKey, // Will be encrypted later with the PIN
    seedPhrase: secretKey
  };
}

bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  const telegramId = String(msg.from.id);

  // Check if the command is used in a private message or group
  if (msg.chat.type !== 'private') {
    return bot.sendMessage(chatId, "🚨 *Please use the start command in a private message (DM) with the bot.*\n\nClick here to start: [Start DM](t.me/Beans_tipbot)", { parse_mode: "Markdown" });
  }

  try {
    const existingUser = await User.findOne({ telegramId });
    if (existingUser) {
      return bot.sendMessage(chatId, `🚀 *You're already registered!*  
🔹 *Wallet Address:* \`${existingUser.walletAddress}\`  

Use /help to see available commands.`, { parse_mode: "Markdown" });
    }

    // Generate a new wallet
    const wallet = await createWallet();
    const words = wallet.seedPhrase.split(' ');
    const randomIndexes = generateUniqueIndexes(words.length, 3);
    const challengeWords = randomIndexes.map(i => words[i]);

    // Send wallet info to user
    const sentMessage = await bot.sendMessage(chatId, `🚨 *IMPORTANT: Secure Your Seed Phrase!* 🚨  

🔹 *Wallet Address:* \`${wallet.address}\`  
🔹 *Seed Phrase:* \`${wallet.seedPhrase}\`  

⚠️ *The bot does NOT store your seed phrase!*  
If you lose it, you lose access to your wallet forever.  
✅ *Write it down and store it securely!*  

⏳ *This message will be deleted in 15 minutes for security.*  

Have you saved your seed phrase?  
1️⃣ Yes, I saved it  
2️⃣ No, I need more time`, {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [{ text: "✅ Yes", callback_data: `seed_saved_${telegramId}` }],
          [{ text: "❌ No", callback_data: `seed_not_saved_${telegramId}` }]
        ]
      }
    });

    // Auto-delete the message after 15 minutes (900000 ms)
    setTimeout(() => {
      bot.deleteMessage(chatId, sentMessage.message_id).catch(() => { });
    }, 900000);

    bot.once("callback_query", async (callbackQuery) => {
      if (!callbackQuery.data.includes(`_${telegramId}`)) return;

      if (callbackQuery.data.startsWith("seed_saved")) {
        bot.deleteMessage(chatId, sentMessage.message_id).catch(() => { });

        bot.sendMessage(chatId, `📌 *Seed phrase verification:*  

Please enter the following words from your seed phrase:
- Word #${randomIndexes[0] + 1}
- Word #${randomIndexes[1] + 1}
- Word #${randomIndexes[2] + 1}

*(Reply in order, separated by spaces)*`, { parse_mode: "Markdown" });

        bot.once("message", async (response) => {
          const userResponse = response.text.trim().split(" ");
          if (
            userResponse.length === 3 &&
            userResponse[0] === challengeWords[0] &&
            userResponse[1] === challengeWords[1] &&
            userResponse[2] === challengeWords[2]
          ) {
            bot.sendMessage(chatId, "✅ *Seed phrase verified!*");

            bot.sendMessage(chatId, "🔐 Please set a 5-digit PIN to secure your wallet.", {
              reply_markup: { force_reply: true }
            }).then((pinRequestMessage) => {
              bot.onReplyToMessage(chatId, pinRequestMessage.message_id, async (msg) => {
                const firstPin = msg.text.trim();

                await bot.deleteMessage(chatId, msg.message_id).catch(() => { });

                if (!/^\d{5}$/.test(firstPin)) {
                  return bot.sendMessage(chatId, "⚠️ Invalid PIN! Must be 5 digits. Try again:");
                }

                const confirmMessage = await bot.sendMessage(chatId, "🔁 Please re-enter your 5-digit PIN to confirm:", {
                  reply_markup: { force_reply: true }
                });

                bot.onReplyToMessage(chatId, confirmMessage.message_id, async (confirmMsg) => {
                  const confirmedPin = confirmMsg.text.trim();

                  await bot.deleteMessage(chatId, confirmMsg.message_id).catch(() => { });

                  if (firstPin !== confirmedPin) {
                    await bot.deleteMessage(chatId, confirmMessage.message_id).catch(() => { });
                    return bot.sendMessage(chatId, "❌ PINs don't match! Start over with /start");
                  }

                  const encryptedPrivateKey = encryptPrivateKey(wallet.privateKey, confirmedPin);

                  await new User({
                    telegramId,
                    username: msg.from.username,
                    walletAddress: wallet.address,
                    encryptedPrivateKey,
                    securityCode: crypto.createHash("sha256").update(confirmedPin).digest("hex")
                  }).save();

                  await bot.deleteMessage(chatId, pinRequestMessage.message_id).catch(() => { });
                  bot.sendMessage(chatId, "✅ Your wallet is secured with your PIN and ready to use! \nUse /help to see available commands.", { parse_mode: "Markdown" });
                });
              });
            });
          } else {
            bot.sendMessage(chatId, "❌ *Incorrect seed phrase verification!* Please use /start again and ensure you have saved your seed phrase correctly.");
          }
        });
      } else if (callbackQuery.data.startsWith("seed_not_saved")) {
        bot.sendMessage(chatId, "⚠️ *Please take your time and save your seed phrase securely.*\nUse /start again when you're ready.");
      }
    });

  } catch (error) {
    console.error("Error creating wallet:", error);
    bot.sendMessage(chatId, "❌ An error occurred while creating your wallet. Please try again later.");
  }
});


bot.onText(/\/resetwallet/, async (msg) => {
  const chatId = msg.chat.id;
  const telegramId = String(msg.from.id);

  const user = await User.findOne({ telegramId });
  if (!user || !user.securityCode) {
    return bot.sendMessage(chatId, "❌ You have no security PIN set. You cannot reset your wallet.");
  }

  // Prompt for the current PIN
  bot.sendMessage(chatId, "🔐 Enter your 5-digit security PIN to reset your wallet:", {
    reply_markup: { force_reply: true }
  }).then((sentMessage) => {
    bot.onReplyToMessage(chatId, sentMessage.message_id, async (pinMsg) => {
      const pinMessageId = pinMsg.message_id;
      const pin = pinMsg.text.trim();
      const encryptedPin = crypto.createHash("sha256").update(pin).digest("hex");

      // Delete the PIN message immediately for security
      bot.deleteMessage(chatId, pinMessageId).catch(() => { });

      if (encryptedPin !== user.securityCode) {
        return bot.sendMessage(chatId, "❌ Incorrect PIN! Wallet reset denied.");
      }

      // Create a new wallet
      const newWallet = await createWallet();
      const words = newWallet.seedPhrase.split(' ');
      const randomIndexes = generateUniqueIndexes(words.length, 3);
      const challengeWords = randomIndexes.map(i => words[i]);

      // Send the new wallet details (seed phrase) to the user
      const sentSeedMsg = await bot.sendMessage(chatId, `🚨 *Your wallet has been reset!* 🚨
            
🔹 *New Wallet Address:* \`${newWallet.address}\`
🔹 *New Seed Phrase:* \`${newWallet.seedPhrase}\`

⚠️ *This will NOT be stored! Write it down securely.*
✅ *Write it down and store it securely!*

⏳ *This message will be deleted in 15 minutes for security.*

Have you saved your seed phrase?
1️⃣ Yes, I saved it
2️⃣ No, I need more time`, {
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [{ text: "✅ Yes", callback_data: `seed_saved_${telegramId}` }],
            [{ text: "❌ No", callback_data: `seed_not_saved_${telegramId}` }]
          ]
        }
      });

      // Auto-delete the seed phrase message after 15 minutes
      setTimeout(() => {
        bot.deleteMessage(chatId, sentSeedMsg.message_id).catch(() => { });
      }, 900000);

      bot.once("callback_query", async (callbackQuery) => {
        if (!callbackQuery.data.includes(`_${telegramId}`)) return;

        if (callbackQuery.data.startsWith("seed_saved")) {
          // Delete the seed phrase message immediately upon confirmation
          bot.deleteMessage(chatId, sentSeedMsg.message_id).catch(() => { });

          // Ask the user to verify their seed phrase by entering 3 words
          bot.sendMessage(chatId, `📌 *Verify your seed phrase:*

Please enter the following words from your seed phrase:
- Word #${randomIndexes[0] + 1}
- Word #${randomIndexes[1] + 1}
- Word #${randomIndexes[2] + 1}

*(Reply in order, separated by spaces)*`, { parse_mode: "Markdown" });

          bot.once("message", async (response) => {
            const userResponse = response.text.trim().split(" ");
            if (
              userResponse.length === 3 &&
              userResponse[0] === challengeWords[0] &&
              userResponse[1] === challengeWords[1] &&
              userResponse[2] === challengeWords[2]
            ) {
              // Encrypt the new wallet's private key using the provided PIN
              const encryptedPrivateKey = encryptPrivateKey(newWallet.privateKey, pin);

              // Update the user record with the new wallet details
              user.walletAddress = newWallet.address;
              user.encryptedPrivateKey = encryptedPrivateKey;
              await user.save();

              bot.sendMessage(chatId, "✅ *Seed phrase verified! Your wallet reset is complete.*", { parse_mode: "Markdown" });
            } else {
              bot.sendMessage(chatId, "❌ *Incorrect seed phrase verification!* Wallet reset failed. Try again with /resetwallet.");
            }
          });
        } else if (callbackQuery.data.startsWith("seed_not_saved")) {
          bot.sendMessage(chatId, "⚠️ *Please take your time and save your seed phrase securely.*\nUse /resetwallet again when you're ready.");
        }
      });
    });
  }).catch((err) => {
    console.error("Error in /resetwallet:", err);
    bot.sendMessage(chatId, "❌ An error occurred while processing your wallet reset. Please try again later.");
  });
});

// Help Command
bot.onText(/\/help/, (msg) => {
  const chatId = msg.chat.id;
  const helpMessage = `
  📘 *Available Commands:*
  
  /start - Create a new wallet or restore an existing wallet  
  /help - Show this help message  
  /balance - Check your wallet balance  
  /tip <amount> <address> - Send STX tokens to a specific address  
  /receive - Get your wallet address  
  /resetwallet - Reset your wallet (requires PIN)  
  /recover - Recover your wallet if you lost your PIN (requires seed phrase)  
  `;
  bot.sendMessage(chatId, helpMessage, { parse_mode: "Markdown" });
});



bot.onText(/\/receive/, async (msg) => {
  const chatId = msg.chat.id;
  const telegramId = String(msg.from.id);

  try {
    const user = await User.findOne({ telegramId });
    if (!user) {
      return bot.sendMessage(chatId, '❌ You are not registered yet. Use /start to register.');
    }

    // Send the user's wallet address
    bot.sendMessage(chatId, `🔹 *Your Wallet Address:* \`${user.walletAddress}\``, { parse_mode: "Markdown" });
  } catch (error) {
    console.error('Error fetching wallet address:', error);
    bot.sendMessage(chatId, '❌ An error occurred while fetching your wallet address. Please try again later.');
  }
});


// If needed, uncomment the following line for Node versions without native fetch support
// const fetch = require('node-fetch');

bot.onText(/\/balance/, async (msg) => {
  const chatId = msg.chat.id;
  const telegramId = String(msg.from.id);

  // Add reply options to all responses
  const replyOptions = {
    reply_to_message_id: msg.message_id // Reply directly to the user's command
  };

  try {
    const user = await User.findOne({ telegramId });
    if (!user) {
      return bot.sendMessage(
        chatId,
        '❌ You are not registered yet. Use /start to register.',
        replyOptions
      );
    }

    const address = user.walletAddress;
    const url = `https://api.hiro.so/extended/v1/address/${address}/balances`;
    const response = await fetch(url);

    if (!response.ok) {
      console.error(`Error fetching balance: HTTP status ${response.status}`);
      return bot.sendMessage(
        chatId,
        '❌ Error fetching your balance. Please try again later.',
        replyOptions
      );
    }

    const accountData = await response.json();

    if (!accountData?.fungible_tokens || !accountData.stx) {
      return bot.sendMessage(
        chatId,
        '❌ Unexpected response structure. Please try again later.',
        replyOptions
      );
    }

    let message = '';

    // STX Balance
    const stxBalance = parseInt(accountData.stx.balance) / 1e6;
    message += `Your STX balance is: ${stxBalance} STX\n`;

    // Mrbeans Balance
    const mrBeansContractAddress = 'SP1MASMF30DRR4KDR5TG4RZEEVHBKS1ZX4TJZ8P06.mrbeans-stxcity::Beans';
    const mrBeansBalanceData = accountData.fungible_tokens[mrBeansContractAddress];

    if (mrBeansBalanceData?.balance) {
      const beansBalance = parseInt(mrBeansBalanceData.balance) / 1e6;
      message += `Your mrbeans token balance is: ${beansBalance} Beans`;
    } else {
      message += 'No mrbeans token balance found.';
    }

    // Send balance with reply
    bot.sendMessage(chatId, message, replyOptions);

  } catch (error) {
    console.error('Error fetching balance:', error);
    bot.sendMessage(
      chatId,
      '❌ An error occurred while fetching your balance. Please try again later.',
      replyOptions
    );
  }
});

/**
 * Decrypts an encrypted private key using the provided PIN combined with PRIVATE_KEY_SECRET.
 */
function decryptPrivateKey(encryptedData, pin) {
  const combinedKey = crypto.createHash('sha256').update(pin + PRIVATE_KEY_SECRET).digest();
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', combinedKey, iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

/**
 * Fetches the current nonce for the provided wallet address from the Stacks network.
 */
async function getNonce(address) {
  const accountUrl = `https://stacks-node-api.mainnet.stacks.co/v2/accounts/${address}`;
  const res = await fetch(accountUrl);
  if (!res.ok) {
    throw new Error('Failed to fetch account data');
  }
  const data = await res.json();
  return data.nonce;
}

/**
 * Tipping command supporting both formats:
 * 1. /tip amount         (used as a reply to a recipient's message)
 * 2. /tip @username amount  (used when not replying)
 *
 * In both cases, a DM is sent to the tipper to securely collect their 5-digit PIN.
 * This version sends Beans tokens via a contract call to the token's "transfer" function.
 */
// Make sure to import the necessary functions and modules.


// Inside your /tip command
bot.onText(/\/tip(?:\s+(@\S+))?\s+(\d+(\.\d+)?)(?:\s+(stx))?/, async (msg, match) => {
  const groupChatId = msg.chat.id;
  const tipperTelegramId = String(msg.from.id);
  const optionalUsername = match[1];
  const tipAmount = parseFloat(match[2]);
  const isStxTip = match[4] === 'stx';
  const tipType = isStxTip ? 'STX' : 'Beans';

  // Declare timeout in this scope
  let timeout;

  try {
    // Validate tip amount
    if (isNaN(tipAmount) || tipAmount <= 0) {
      return bot.sendMessage(groupChatId, "❌ Invalid tip amount provided.");
    }

    // Look up the tipper
    const tipper = await User.findOne({ telegramId: tipperTelegramId });
    if (!tipper) {
      return bot.sendMessage(groupChatId, "❌ You are not registered. Use /start to register.");
    }

    // Determine the recipient
    let recipient;
    if (msg.reply_to_message) {
      const recipientTelegramId = String(msg.reply_to_message.from.id);
      recipient = await User.findOne({ telegramId: recipientTelegramId });
      if (!recipient) {
        return bot.sendMessage(groupChatId, "❌ The recipient is not registered.");
      }
    } else if (optionalUsername) {
      const username = optionalUsername.replace('@', '');
      recipient = await User.findOne({ username });
      if (!recipient) {
        return bot.sendMessage(groupChatId, `❌ @${username} is not registered.`);
      }
    } else {
      return bot.sendMessage(groupChatId, "❌ Please reply to a user's message or specify @username.");
    }

    // Notify the group (replying to the original tip message) to check their DM
    await bot.sendMessage(
      groupChatId,
      `@${msg.from.username || tipperTelegramId}, check your DMs to confirm your ${tipType} tip.`,
      { reply_to_message_id: msg.message_id }
    );

    // Send a DM to the tipper prompting for their 5-digit PIN
    const dmMsg = await bot.sendMessage(
      tipperTelegramId,
      `You are tipping ${tipAmount} ${tipType} to @${recipient.username || recipient.telegramId}.\n` +
      "Please reply with your 5-digit PIN to confirm the tip:",
      { reply_markup: { force_reply: true } }
    );

    // Set up a reply listener in DM
    const replyListener = async (replyMsg) => {
      try {
        // Validate that this reply is in DM, from the same tipper, and replying to our DM
        if (
          !replyMsg.reply_to_message ||
          replyMsg.reply_to_message.message_id !== dmMsg.message_id ||
          String(replyMsg.from.id) !== tipperTelegramId
        ) {
          return;
        }

        // Remove listener and cancel the timeout
        bot.removeListener('message', replyListener);
        clearTimeout(timeout);

        // Process the PIN
        const pin = replyMsg.text.trim();
        await bot.deleteMessage(tipperTelegramId, replyMsg.message_id).catch(() => {});

        // Decrypt the tipper's private key using the provided PIN
        let decryptedPrivateKey;
        try {
          decryptedPrivateKey = decryptPrivateKey(tipper.encryptedPrivateKey, pin);
        } catch (error) {
          return bot.sendMessage(tipperTelegramId, "❌ Invalid PIN. Tip cancelled.");
        }

        // Define contract constants
        const tippingContractAddress = 'SP268NSDNZ8THZ9C1K995MVXKGYT4JNQH82DDM34T';
        const tippingContractName = 'beans';
        const fee = 4000n; // microSTX, fixed fee from the contract
        const nonce = await getNonce(tipper.walletAddress);

        let functionName, functionArgs, postConditions;

        if (isStxTip) {
          // STX tip: Convert amount to microSTX and include fee
          const amountStx = BigInt(Math.round(tipAmount * 1e6));
          const totalStx = amountStx + fee;
          functionName = 'tip-stx';
          functionArgs = [
            principalCV(recipient.walletAddress),
            uintCV(amountStx),
            noneCV() // No memo for simplicity
          ];
          postConditions = [
            Pc.principal(tipper.walletAddress).willSendEq(totalStx).ustx()
          ];
        } else {
          // Beans tip: Use the Beans token contract
          const tokenContract = 'SP1MASMF30DRR4KDR5TG4RZEEVHBKS1ZX4TJZ8P06.mrbeans-stxcity';
          const amountBeans = BigInt(Math.round(tipAmount * 1e6));
          functionName = 'tip-ft';
          functionArgs = [
            principalCV(tokenContract),
            principalCV(recipient.walletAddress),
            uintCV(amountBeans),
            noneCV() // No memo for simplicity
          ];
          postConditions = [
            Pc.principal(tipper.walletAddress).willSendEq(fee).ustx(),              // STX fee
            Pc.principal(tipper.walletAddress).willSendEq(amountBeans).ft(tokenContract, 'Beans') 
          ];
        }

        // Define transaction options
        const txOptions = {
          contractAddress: tippingContractAddress,
          contractName: tippingContractName,
          functionName: functionName,
          functionArgs: functionArgs,
          senderKey: decryptedPrivateKey,
          fee: BigInt(1000), // Transaction fee in microSTX
          nonce: nonce.toString(),
          network: 'mainnet',
          postConditions: postConditions,
          postConditionMode: PostConditionMode.Allow
        };

        // Create and broadcast the transaction
        const transaction = await makeContractCall(txOptions);
        if (!transaction) {
          throw new Error("Transaction creation failed");
        }

        // console.log("Transaction Object:", transaction);

        const result = await broadcastTransaction({ transaction, network });
        if (result.error) {
          throw new Error(`Broadcast failed: ${result.error}`);
        }
        const explorerLink = `https://explorer.hiro.so/txid/${result.txid}?chain=mainnet`;
        console.log("Broadcast Result:", result);

        // Notify the tipper in DM
        await bot.sendMessage(
          tipperTelegramId,
          `✅ ${tipAmount} ${tipType} sent successfully!\nTX ID: ${explorerLink}`
        );

        // Notify the group (replying to the original tip message)
        await bot.sendMessage(
          groupChatId,
          `✅ ${tipAmount} ${tipType} tip from @${msg.from.username || tipperTelegramId} to @${recipient.username || recipient.telegramId}!`,
          { reply_to_message_id: msg.message_id }
        );

      } catch (error) {
        console.error("Tip processing error:", error);
        bot.sendMessage(
          tipperTelegramId,
          "❌ Transaction failed. Please try again later."
        );
      }
    };

    // Set up the DM reply listener with a 5-minute timeout
    bot.on('message', replyListener);
    timeout = setTimeout(() => {
      bot.removeListener('message', replyListener);
      bot.sendMessage(tipperTelegramId, "⌛ Tip confirmation timed out.");
    }, 300000);

  } catch (error) {
    console.error("Tip command error:", error);
    bot.sendMessage(groupChatId, "❌ An error occurred. Please try again.");
  }
});


// /recover command implementation
bot.onText(/\/recover/, async (msg) => {
  const chatId = msg.chat.id;
  const telegramId = String(msg.from.id);
  const isGroupChat = msg.chat.type !== 'private';

  if (isGroupChat) {
    return bot.sendMessage(chatId, "🚨 *Please use the recover command in a private message (DM) with the bot.*\n\nClick here to start: [Start DM](t.me/Beans_tipbot)", { parse_mode: "Markdown" });
  }

  try {
    const existingUser = await User.findOne({ telegramId });
    if (!existingUser) {
      return bot.sendMessage(chatId, "❌ *You are not registered yet.* Please start by registering first.");
    }

    // Ask the user to provide their seed phrase
    const seedMessage = await bot.sendMessage(chatId, "🔑 Please enter your seed phrase to recover your wallet:");

    // Listen for seed phrase input
    bot.once('message', async (response) => {
      if (response.chat.id !== chatId || !response.text) return;

      const providedSeedPhrase = response.text.trim();

      try {
        // Generate wallet from provided seed phrase
        const wallet = await createWalletFromSeed(providedSeedPhrase);
        const generatedAddress = wallet.address;
        const newPrivateKey = wallet.privateKey; // New private key from recovered wallet

        // Compare the generated address with the stored address
        if (generatedAddress !== existingUser.walletAddress) {
          return bot.sendMessage(chatId, "❌ *The provided seed phrase doesn't match the registered wallet address.*\n\nWould you like to try entering your seed phrase again? Type /recover to restart the process.", { parse_mode: "Markdown" });
        }

        // If the addresses match, ask the user for a new PIN
        bot.sendMessage(chatId, "✅ *Seed phrase confirmed.* Please set a new 5-digit PIN to secure your wallet.", {
          reply_markup: { force_reply: true }
        }).then((pinRequestMessage) => {
          // Listen for PIN input
          bot.once('message', async (pinMsg) => {
            const newPin = pinMsg.text.trim();

            // Validate new PIN
            if (!/^\d{5}$/.test(newPin)) {
              return bot.sendMessage(chatId, "⚠️ Invalid PIN! Must be 5 digits. Try again:");
            }

            // Ask for PIN confirmation
            const confirmMessage = await bot.sendMessage(chatId, "🔁 Please re-enter your new 5-digit PIN to confirm:", {
              reply_markup: { force_reply: true }
            });

            // Listen for PIN confirmation
            bot.once('message', async (confirmMsg) => {
              const confirmedPin = confirmMsg.text.trim();

              // Compare both PIN entries
              if (newPin !== confirmedPin) {
                return bot.sendMessage(chatId, "❌ PINs don't match! Start over with /recover.");
              }

              // Encrypt the new private key with the new PIN
              const encryptedPrivateKey = encryptPrivateKey(newPrivateKey, newPin);

              // Save new PIN and encrypted private key to the user
              existingUser.securityCode = crypto.createHash("sha256").update(newPin).digest("hex");
              existingUser.encryptedPrivateKey = encryptedPrivateKey;
              await existingUser.save();

              // Success message
              bot.sendMessage(chatId, "✅ Your wallet is recovered and secured with your new PIN.");
            });
          });
        });
      } catch (error) {
        if (error.message === "Not a valid bip39 mnemonic") {
          return bot.sendMessage(chatId, "❌ *Invalid mnemonic phrase provided. Please check the seed phrase and try again. /recover*", { parse_mode: "Markdown" });
        } else {
          console.error("Error during recovery:", error);
          return bot.sendMessage(chatId, "❌ *An error occurred while recovering your wallet. Please try again later. /recover*", { parse_mode: "Markdown" });
        }
      }
    });

  } catch (error) {
    console.error("Error during recovery:", error);
    bot.sendMessage(chatId, "❌ *An error occurred while recovering your wallet. Please try again later.*", { parse_mode: "Markdown" });
  }
});


async function createWalletFromSeed(seedPhrase) {
  // Implement wallet creation using the provided seed phrase and return wallet object
  try {
    const wallet = await generateWallet({ secretKey: seedPhrase, password: 'password' });
    const account = wallet.accounts[0];
    const address = getStxAddress({ account, transactionVersion: TransactionVersion });

    return {
      address,
      privateKey: account.stxPrivateKey // Return the new private key for encryption
    };
  } catch (error) {
    throw new Error("Not a valid bip39 mnemonic"); // Customize the error message if needed
  }
}




app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});