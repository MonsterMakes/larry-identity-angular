import { Injectable } from '@angular/core';
import {
	HttpRequest,
	HttpHandler,
	HttpEvent,
	HttpInterceptor
} from '@angular/common/http';
import { UserSessionService, SessionDetails } from '../services/user-session.service';
import { Observable, from } from 'rxjs';
import { switchMap } from 'rxjs/operators';


@Injectable()
export class AccessTokenInterceptor implements HttpInterceptor {
	constructor(public _userSession: UserSessionService) { }
	_isSameOrigin(destUrl,aud){
		let allowedUrls = [].concat(aud);
		let notSameOrigin = allowedUrls.every((allowedUrlStr)=>{
			let audienceUrl = new URL(allowedUrlStr);
			if(destUrl.hostname.includes(audienceUrl.hostname)){
				return false;
			}
			else{
				return true;
			}
		});
		return !notSameOrigin;
	}
	intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
		let destUrl = new URL(request.url,window.location.origin);
		let sessionDeets;
		let accessTkn;
		return from(	
				Promise.resolve()
					.then(()=>{
						return this._userSession.getSessionDetails()
					})
					.then((sessionDetails: SessionDetails)=>{
						sessionDeets = sessionDetails;
						return this._userSession.getAccessToken();
					})
			).pipe(switchMap((access_token) => {
				accessTkn = access_token;
				if(sessionDeets){
					if(this._isSameOrigin(destUrl,accessTkn.aud)){
						const headers = request.headers
							.set('Authorization', 'Bearer ' + sessionDeets.access_token)
						const requestClone = request.clone({headers });
						return next.handle(requestClone);
					}
					else{
						console.debug(`AccessTokenInterceptor intercepted a request to ${request.url}, this is not the same origin as found in the aud clain (${accessTkn.aud}), for security reasons we will not send the access token to this system`);
					}
				}
				
				return next.handle(request);
			}));
	}
}
