import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
	selector: 'lry-silent-code-callback',
	template: '',
	styleUrls: []
})
export class SilentCodeCallbackComponent implements OnInit {

	constructor(
		private _currentRoute: ActivatedRoute,
	) { }

	async ngOnInit() {
		console.debug('Silent code Callback recieved...', {
			routeInfo: this._currentRoute,
			params: this._currentRoute.snapshot.queryParams
		});
		// if oidc flow error
		let error = this._currentRoute.snapshot.queryParams.error;
		let rawRequestDetails = {
			queryParams: this._currentRoute.snapshot.queryParams,
			hash: this._currentRoute.snapshot.fragment,
			routeData: this._currentRoute.snapshot.data,
			href: window.location.href
		};

		if(error){
			window.parent.postMessage(
				{
					error,
					error_description: this._currentRoute.snapshot.queryParams.error_description,
					extraDetails: rawRequestDetails
				},
				window.location.origin
			);
		}
		else{
			window.parent.postMessage(
				{
					code: this._currentRoute.snapshot.queryParams.code,
					extraDetails: rawRequestDetails
				},
				window.location.origin
			);
		}
	}
}
