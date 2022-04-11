import { Client, Intents } from "discord.js";

export class DiscordClient extends Client {
  constructor() {
    super({
      intents: [
        Intents.FLAGS.GUILD_MESSAGES,
        Intents.FLAGS.GUILDS,
        Intents.FLAGS.GUILD_MEMBERS,
      ],
      partials: ["GUILD_MEMBER"],
    });
  }
}
