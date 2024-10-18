// Cynhyrchwyd y ffeil hon yn awtomatig. PEIDIWCH Â MODIWL
// This file is automatically generated. DO NOT EDIT
import {events} from '../models';
import {models} from '../models';

export function DisableProxy():Promise<events.Event>;

export function EnableProxy():Promise<events.Event>;

export function GenerateCert():Promise<events.Event>;

export function GetConfig():Promise<models.Config>;

export function InstallCert():Promise<events.Event>;

export function SetConfig(arg1:models.Config):Promise<void>;

export function StartProxy():Promise<events.Event>;

export function StopProxy():Promise<events.Event>;

export function Test():Promise<string>;

export function UninstallCert():Promise<events.Event>;
