import { Component, OnInit } from '@angular/core';
import { UamEnvironmentService } from '../../services/uam-environment.service';
import { ActivatedRoute } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import * as _ from 'lodash';

@Component({
	selector: 'lry-code-callback',
	templateUrl: './code-callback.component.html',
	styleUrls: ['./code-callback.component.scss']
})
export class CodeCallbackComponent implements OnInit {
	__errorDetails: { error: any; description: any; };

	constructor(
		private _authService: AuthService,
		private _currentRoute: ActivatedRoute,
	) { }

	_handleError(errorTitle: string, errorDescription:string){
		this.__errorDetails = {
			error: errorTitle,
			description: errorDescription
		}
	}

	async _makeTokenRequest(){
		let authorizationCode = this._currentRoute.snapshot.queryParams.code;
		try{
			await this._authService.exchangeCodeForToken(authorizationCode);
		}
		catch(err){
			// known oauth error
			if(_.get(err,'error.error')){
				this._handleError(err.error.error, err.error.error_description);
			}
			else{
				this._handleError('Unknown Error','We have encountered an unexpected situation. Please check the console for more details.');
			}
		}
	}

	async ngOnInit() {
		console.debug('Code Callback recieved...', {
			routeInfo: this._currentRoute,
			params: this._currentRoute.snapshot.queryParams
		});
		// if oidc flow error
		let error = this._currentRoute.snapshot.queryParams.error;
		if(error){
			this._handleError(error,this._currentRoute.snapshot.queryParams.error_description);
		}
		else{
			this._makeTokenRequest();
		}
	}
}
