import { BaseCommandInteraction, Interaction } from "discord.js";
import { Commands } from "../commands";

export default async (interaction: Interaction) => {
  if (interaction.isCommand() || interaction.isContextMenu()) {
    for (const Command of Commands) {
      if (interaction.commandName === Command.data.name) {
        await Command.run(interaction);
        break;
      }
    }
  }
};
