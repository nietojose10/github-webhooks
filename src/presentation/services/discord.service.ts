import { envs } from '../../config';


export class DiscordService {

    private readonly discordWebhookUrl = envs.DISCORD_WEBHOOK_URL;

    constructor() {}

    async notify( message: string ) {

        const body = {
            content: message,
            embeds: [
                {
                    image: { url: 'https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExNGU5OXZyYjkxZ2Q5dHR4OHZvdWU3cTF0aXkzdXg3bTNxdjMya3d5eSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/3oKIPnAiaMCws8nOsE/giphy.gif'}
                }
            ]
        }

        const response = await fetch( this.discordWebhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        if ( !response.ok ) {
            console.log('Error sending message to discord');
            return false;
        }

        return true;
    }

}