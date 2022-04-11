import { SlashCommandBuilder } from "@discordjs/builders";
import { CommandInteraction } from "discord.js";
import { Command } from "../interfaces/command";

export const Ping: Command = {
  data: new SlashCommandBuilder()
    .setName("ping")
    .setDescription("Check for bot connectivity"),
  run: async (interaction: CommandInteraction) => {
    const message = await interaction.channel.send("Pinging...");

    let botping = Math.round(interaction.client.ws.ping);
    let ping = interaction.createdTimestamp - message.createdTimestamp;

    await message.delete();

    await interaction.reply({
      content: `WS: ${botping}, Ping: ${ping}`,
    });
  },
};
