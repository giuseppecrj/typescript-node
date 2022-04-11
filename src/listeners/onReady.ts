import { DiscordClient } from "../client";
import { REST } from "@discordjs/rest";
import { Routes } from "discord-api-types/v9";

import { Commands } from "../commands";

export default async (client: DiscordClient): Promise<void> => {
  if (!client.user || !client.application) return;

  const rest = new REST({ version: "9" }).setToken(process.env.BOT_TOKEN);
  const commandData = Commands.map((command) => command.data.toJSON());

  await rest.put(
    Routes.applicationGuildCommands(
      client.user?.id || "missing id",
      process.env.GUILD_ID
    ),
    { body: commandData }
  );

  console.log(`${client.user.username} is online`);
};
