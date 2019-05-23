import { NgModule, APP_INITIALIZER } from '@angular/core';
import { CommonModule } from '@angular/common';

import { AuthRoutingModule } from './auth.routing.module';
import { UamEnvironmentService } from './services/uam-environment.service';

import { LoginComponent } from './components/login/login.component';
import { CodeCallbackComponent } from './components/code-callback/code-callback.component';
import { UserSessionService } from './services/user-session.service';
import { AuthService } from './services/auth.service';
import { SilentCodeCallbackComponent } from './components/silent-code-callback/silent-code-callback.component';
import { LoggedOutComponent } from './components/logged-out/logged-out.component';
import { LogoutComponent } from './components/logout/logout.component';
import { LandingComponent } from './components/landing/landing.component';
import { AccessTokenInterceptor } from './http-interceptors/access-token.interceptor';

@NgModule({
  declarations: [
	  LoginComponent, 
	  CodeCallbackComponent,
	  SilentCodeCallbackComponent,
	  LoggedOutComponent,
	  LogoutComponent,
	  LandingComponent
  ],
  imports: [
	AuthRoutingModule,
	CommonModule
  ],
  exports: [
	  
  ],
  providers: [
	UamEnvironmentService,
	UserSessionService,
	AuthService,
	AccessTokenInterceptor
  ]
})
export class AuthModule {
	constructor() {} 
}
