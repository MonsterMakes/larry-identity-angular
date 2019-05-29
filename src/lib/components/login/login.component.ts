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

	async ngOnInit() {
		this._authService.login();
	}
}
