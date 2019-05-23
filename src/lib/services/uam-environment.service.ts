import { Injectable } from '@angular/core';
import * as _ from 'lodash';

const CACHE_PERIOD_MIN = 30;

export interface UamEnvironmentDetails{
	apiUrl: string; //the apiUrl of the UAM services (User and Account Management)
	clientId: string;
	cachedAt: number; //epoch time when this object was cached
}
export interface EnvironmentDetails{
	uam: UamEnvironmentDetails
}

@Injectable({
	providedIn: 'root'
})
export class UamEnvironmentService {

	private _environmentDetails: UamEnvironmentDetails;
	private _loadingProm: Promise<UamEnvironmentDetails>;

	constructor() { }

	/**
	 * Loads the environment details from the sever or the local cache if it has not expired.
	 */
	load(): Promise<UamEnvironmentDetails> {
		this._environmentDetails = null;
		const ENV_DETAILS_URL = this._getEnvironmentDetailsUrl();
		const localUrl = '/environment-details.json';
		this._loadingProm = Promise.resolve()
			// check if this request has been made within CACHE_PERIOD
			.then(()=>{
				let envDetails = null;
				let cache = window.sessionStorage.getItem(ENV_DETAILS_URL);
				if(cache){
					try{
						envDetails = JSON.parse(cache);
						let cachedAt = envDetails.cachedAt;
						// check to see if CACHE_PERIOD has passed
						if(cachedAt){
							let currentTime = Date.now();
							let elapsedMs = currentTime-cachedAt;
							let elapsedMin = Math.ceil(elapsedMs / (1000*60));
							if(elapsedMin > CACHE_PERIOD_MIN){
								envDetails = null;
							}
						}
					}
					catch(e){
						//this is not something worth displaying as error... instead we will debug it so its not swallowed
						console.debug(`Failed to parse Environment Details from SessionStorage.${ENV_DETAILS_URL}.`,{valueInSessionStorage: cache});
					}
				}
				return envDetails;
			})
			.then((cachedEnvDetails)=>{
				// previously cached use it
				if(cachedEnvDetails){
					return cachedEnvDetails;
				}
				// not cached go retrieve it
				else{
					return	window.fetch(ENV_DETAILS_URL)
						.catch(err => {
							console.log(`Failed to load Environment Details from (${ENV_DETAILS_URL}), loading them from (${localUrl}) instead.`);
							return window.fetch(localUrl);
						})
						.then((response: Response) => {
							return response.json();
						});
				}
			})
			.then((data) => {
				this._setEnvironmentDetails(data);
				return this._environmentDetails;
			})
			.catch((err: any) => {
				console.error(`Failed to load Environment Details from (${ENV_DETAILS_URL}) and from (${localUrl}), contact support.`);
				return Promise.reject(err);
			});
		return this._loadingProm;
	}
	whenLoaded(): Promise<UamEnvironmentDetails> {
		if(this._loadingProm){
			return this._loadingProm;
		}
		else{
			return this.load();
		}
	}
	_getEnvironmentDetailsUrl(){
		return location.protocol + '//uam.' + location.hostname + '/environment/details';
	}
	_setEnvironmentDetails(envDeets: UamEnvironmentDetails): void {
		this._environmentDetails = <UamEnvironmentDetails> envDeets;
		//cache the details
		let cache = JSON.stringify(_.merge({},this._environmentDetails,{cachedAt: Date.now()}));
		window.sessionStorage.setItem(this._getEnvironmentDetailsUrl(),cache);
	}
	get cachedAt(){
		return this._environmentDetails.cachedAt || null;
	}
	get environmentDetails(): UamEnvironmentDetails {
		return this._environmentDetails;
	}
	get baseUrl(): string {
		const baseUrl = location.protocol + '//' + location.host + '/';
		return baseUrl;
	}
	get apiUrl(): string {
		return _.get(this._environmentDetails,'uam.apiUrl');
	}
	get clientId(): string {
		return _.get(this._environmentDetails,'uam.clientId');		
	}
	get roleClaim(): string {
		return _.get(this._environmentDetails,'uam.roleClaim');
	}
}
