import { Injectable } from '@angular/core';
import { UamEnvironmentService } from './uam-environment.service';
const jwt_decode = require('jwt-decode');

export interface SessionDetails{
	access_token: string,
	id_token: string,
	scope: string,
	expires_in: number,
	token_type: string
}
@Injectable({
	providedIn: 'root'
})
export class UserSessionService {
	
	constructor( private _uamEnvironmentService: UamEnvironmentService ) { 
	}

	/*********************************************************************************/
	/*********************************************************************************/
	/* START PUBLIC METHODS */
	/*********************************************************************************/
	/*********************************************************************************/
	
	/**
	 * Figure out when the current session will expire, if no session is active null will be returned.
	 */
	async whenWillSessionExpire(): Promise<Date>{
		await this._uamEnvironmentService.whenLoaded();
		let accessToken = window.sessionStorage.getItem(`${this._uamEnvironmentService.apiUrl}access_token`);
		let idToken = window.sessionStorage.getItem(`${this._uamEnvironmentService.apiUrl}id_token`);
		if(accessToken && idToken){
			let accessJwt = <{exp: number}> jwt_decode(accessToken);
			let idJwt = <{exp: number}> jwt_decode(idToken);
			// need to validate that these tokens have not expired (exp is in SECONDS since epoch not ms...)
			let expireEpoch = Math.min(accessJwt.exp,idJwt.exp);
			return new Date(expireEpoch * 1000);
		}
		else{
			return null;
		}
	}

	/**
	 * Is the current session active? More specifically do we have tokens that have not yet expired?
	 * 
	 * Note: This does not check the validity of the tokens just if they are malformed and if they have expired or not.
	 */
	async isSessionActive(): Promise<boolean>{
		await this._uamEnvironmentService.whenLoaded();
		//go to session storage for accessToken/idToken
		let accessToken = window.sessionStorage.getItem(`${this._uamEnvironmentService.apiUrl}access_token`);
		let idToken = window.sessionStorage.getItem(`${this._uamEnvironmentService.apiUrl}id_token`);
		if(accessToken && idToken){
			let accessJwt = <{exp: number}> jwt_decode(accessToken);
			let idJwt = <{exp: number}> jwt_decode(idToken);
			// need to validate that these tokens have not expired (exp is in SECONDS since epoch not ms...)
			let expireEpoch = Math.min(accessJwt.exp,idJwt.exp);
			if(Math.floor(Date.now() / 1000) >= expireEpoch){
				return false;
			}
			else{
				return true;
			}
		}
		// No active session so we need to start the login process
		else {
			return false;
		}
	}

	/**
	 * Get the current session details, if no session is active null will be returned.
	 */
	async getSessionDetails(): Promise<SessionDetails>{
		await this._uamEnvironmentService.whenLoaded();
		if(await this.isSessionActive()){
			return {
				access_token: window.sessionStorage.getItem(`${this._uamEnvironmentService.apiUrl}access_token`),
				id_token: window.sessionStorage.getItem(`${this._uamEnvironmentService.apiUrl}id_token`),
				scope: window.sessionStorage.getItem(`${this._uamEnvironmentService.apiUrl}scope`),
				expires_in: Number(window.sessionStorage.getItem(`${this._uamEnvironmentService.apiUrl}expires_in`)),
				token_type: window.sessionStorage.getItem(`${this._uamEnvironmentService.apiUrl}token_type`)
			}
		}
		else{
			return null;
		}
	}
	
	/**
	 * Get the current active session's decoded access token, null if session is not active
	 * 
	 * Note: This does not check the validity of the access token just that its not malformed or expired.
	 */
	async getAccessToken(): Promise<object>{
		let sessionDetails = await this.getSessionDetails();
		if(sessionDetails){
			let token = sessionDetails.access_token;
			let jwt = jwt_decode(token);
			return jwt;
		}
		else{
			return null;
		}
	}

	/**
	 * Gets an array of the current user's roles, null if session is not active
	 * 
	 * Note: This does not check the validity of the access token just that its not malformed or expired.
	 */
	async getUserRoles(): Promise<object>{
		let sessionDetails = await this.getSessionDetails();
		if(sessionDetails){
			let token = sessionDetails.access_token;
			let jwt = jwt_decode(token);
			if(jwt[this._uamEnvironmentService.roleClaim]){
				return jwt[this._uamEnvironmentService.roleClaim];
			}
			else{
				return [];
			}
			return jwt;
		}
		else{
			return null;
		}
	}

	/**
	 * Get the current active session's decoded id token, null if session is not active
	 * 
	 * Note: This does not check the validity of the id token just that its not malformed or expired.
	 */
	async getIdToken(): Promise<object>{
		let sessionDetails = await this.getSessionDetails();
		if(sessionDetails){
			let token = sessionDetails.id_token;
			let jwt = jwt_decode(token);
			return jwt;
		}
		else{
			return null;
		}
	}
	
	/*********************************************************************************/
	/*********************************************************************************/
	/* END PUBLIC METHODS */
	/* START PROTECTED METHODS */
	/*********************************************************************************/
	/*********************************************************************************/

	/**
	 * This is a protected method and should only be called by the auth module itself.
	 * It sets the current session details from the response of the authorization code grant flow.
	 */
	async __setSessionDetails(details: SessionDetails): Promise<any>{
		await this._uamEnvironmentService.whenLoaded();
		let currentDetails = await this.getSessionDetails();

		//if session details are already set let the developer know
		if(currentDetails){
			console.debug("Session details are being overidden, if the tokens are being refreshed this is a normal scenario...",{
				currentSessionDetails: currentDetails,
				newSessionDetails: details
			});
		}
		// Store response in sessionStorage
		window.sessionStorage.setItem(`${this._uamEnvironmentService.apiUrl}access_token`,details.access_token);
		window.sessionStorage.setItem(`${this._uamEnvironmentService.apiUrl}id_token`,details.id_token);
		window.sessionStorage.setItem(`${this._uamEnvironmentService.apiUrl}scope`,details.scope);
		window.sessionStorage.setItem(`${this._uamEnvironmentService.apiUrl}expires_in`,details.expires_in.toString());
		window.sessionStorage.setItem(`${this._uamEnvironmentService.apiUrl}token_type`,details.token_type);
	}

	/**
	 * This is a protected method and should only be called by the auth module itself.
	 * It will clear the current session.
	 */
	async __clearSession(): Promise<undefined>{
		await this._uamEnvironmentService.whenLoaded();
		window.sessionStorage.removeItem(`${this._uamEnvironmentService.apiUrl}access_token`);
		window.sessionStorage.removeItem(`${this._uamEnvironmentService.apiUrl}id_token`);
		window.sessionStorage.removeItem(`${this._uamEnvironmentService.apiUrl}scope`);
		window.sessionStorage.removeItem(`${this._uamEnvironmentService.apiUrl}expires_in`);
		window.sessionStorage.removeItem(`${this._uamEnvironmentService.apiUrl}token_type`);
		return;
	}

	/*********************************************************************************/
	/*********************************************************************************/
	/* END PROTECTED METHODS */
	/*********************************************************************************/
	/*********************************************************************************/

}