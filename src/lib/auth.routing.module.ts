import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { LoginComponent } from './components/login/login.component';
import { CodeCallbackComponent } from './components/code-callback/code-callback.component';
import { SilentCodeCallbackComponent } from './components/silent-code-callback/silent-code-callback.component';
import { LoggedOutComponent } from './components/logged-out/logged-out.component';
import { LogoutComponent } from './components/logout/logout.component';
import { LandingComponent } from './components/landing/landing.component';

const routes: Routes = [
	{ 
		path: 'auth',
		children: [
			{ path: 'login', component: LoginComponent },
			{ path: 'code-callback', component: CodeCallbackComponent },
			{ path: 'landing', component: LandingComponent },
			{ path: 'silent-code-callback', component: SilentCodeCallbackComponent },
			{ path: 'logout', component: LogoutComponent },
			{ path: 'logged-out', component: LoggedOutComponent }
		]
	}
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class AuthRoutingModule { }
