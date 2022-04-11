import "dotenv/config";

import { validateEnv } from "./utils";
import { DiscordClient } from "./client";
import interactionCreate from "./listeners/onInteraction";
import onReady from "./listeners/onReady";
import onInteraction from "./listeners/onInteraction";

(async () => {
  if (!validateEnv()) return;

  const bot = new DiscordClient();

  bot.on("ready", async () => await onReady(bot));
  bot.on(
    "interactionCreate",
    async (interaction) => await onInteraction(interaction)
  );

  await bot.login(process.env.BOT_TOKEN);
})();
