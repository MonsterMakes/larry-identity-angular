import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
	selector: 'lry-login',
	template: '',
	styleUrls: []
})
export class LoginComponent implements OnInit {

	constructor(
		private _authService: AuthService,
		private _currentRoute: ActivatedRoute
	) { }

	_getPropFromRoute(propName: string, propDefault: string): string {
		let propValue = propDefault;
		const routeData = this._currentRoute.snapshot.data;
		const routeQueryParams = this._currentRoute.snapshot.queryParams;

		// If angular route data provides the redirect_uri use it
		if (routeData[propName]) {
			propValue = routeData[propName];
		}
		// If the query params provide the redirect_uri use it
		else if (routeQueryParams[propName]) {
			propValue = routeQueryParams[propName];
		}
		return propValue;
	}

	_getStateParam(): string {
		return this._getPropFromRoute('state', undefined);
	}

	async ngOnInit() {
		this._authService.login(this._getStateParam());
	}
}
