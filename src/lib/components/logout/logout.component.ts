import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { ErrorDetails } from '../../interfaces/error-details.interface';

@Component({
  selector: 'lry-logout',
  template: '',
  styleUrls: []
})
export class LogoutComponent implements OnInit {

	constructor(
		private _authService: AuthService,
		private _currentRoute: ActivatedRoute
	) { }

	_getCauseParam(): ErrorDetails {
		let errorDeets = undefined;
		let causeParam = this._currentRoute.snapshot.queryParams.cause;
		let causeData = this._currentRoute.snapshot.data.cause;
		if(causeParam){
			try{
				let decodedCauseParam = AuthService.base64UrlDecode(causeParam);
				
				try{
					errorDeets = JSON.parse(decodedCauseParam);
				}
				catch(jsonError){
					console.error('Cause was supplied as a query patam but is invalid JSON...', { causeParam: causeParam });
				}
			}
			catch(b64UrlDecodeErr){
				errorDeets = causeParam;//send it raw
			}
		}
		else if(causeData){
			errorDeets = causeData;
		}
		return errorDeets;
	}

	async ngOnInit() {
		await this._authService.logout(this._getCauseParam());
	}

}
