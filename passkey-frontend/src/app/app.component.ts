import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import {HttpClient, HttpClientModule} from "@angular/common/http";
import {CommonModule} from "@angular/common";
import {FormsModule} from "@angular/forms";
import {fido2Create, fido2Get} from "@ownid/webauthn";

type OpRes = { res?: boolean };

@Component({
  selector: 'app-root',
  template: `
    <div>
      <h1>Passkeys Example</h1>
      <input [(ngModel)]="username" placeholder="Username" />
      <button (click)="registerStart()">Register</button>
      <button (click)="loginStart()">Login</button>
    </div>
  `,
  standalone: true,
  imports: [FormsModule, CommonModule, HttpClientModule]
})
export class AppComponent {
  title = 'passkey-frontend';
  username: string = '';
  constructor(private http: HttpClient) { }

  async registerStart() {
    const publicKey = await this.http.post('/register/start', { username: this.username }).toPromise();
    const fidoData = await fido2Create(publicKey, this.username);
    const result = await this.http.post<OpRes>('/register/finish', fidoData).toPromise();
    alert(`Register successful: ${result?.res}`);
  }

  async loginStart() {
    const response = await this.http.post('/login/start', { username: this.username }).toPromise();
    const options = response as PublicKeyCredentialRequestOptions;
    const assertion = await fido2Get(options, this.username);
    const result = await this.http.post<OpRes>('/login/finish', assertion).toPromise();
    alert(`Login successful: ${result?.res}`);
  }
}
