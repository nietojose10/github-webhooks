import crypto from "crypto";
import express, { NextFunction, Request, Response } from 'express';
import { envs } from '../../config';

const secretKey = envs.SECRET_TOKEN;

export class GithubSha256Middleware {

    static verifySignature = async ( req: Request, res: Response, next: NextFunction ) => {

        const signature = req.header("x-hub-signature-256") ?? '';

        const expectedSignature = "sha256=" + crypto.createHmac( "sha256", secretKey )
        .update( JSON.stringify( req.body ) )
        .digest( "hex" );

        if ( signature !== expectedSignature ) {
            res.status( 401 ).send( "Unauthorized" );
            return;
        }
        
        next();
    };

}