# Okta Thread Detection with Microsoft Sentinel
20 Okta SOC Thread Detection alerts for Microsoft Sentinel

[Read this blog post for more information.](https://cryptsus.com/blog/okta-iam-threat-hunting-siem-use-cases.html)

**1. Okta administrator successfully logs in from a new country OR a new geo-location OR a new device**
```
Okta_CL
  | where isnotempty(actor_alternateId_s)
  | where eventType_s == "user.session.access_admin_app"
  | where outcome_result_s == "SUCCESS"
  | where parse_json(tostring(parse_json(debugContext_debugData_logOnlySecurityData_s).behaviors)).["New Country"] == "POSITIVE" or parse_json(tostring(parse_json(debugContext_debugData_logOnlySecurityData_s).behaviors)).["New Geo-Location"] == "POSITIVE" or parse_json(tostring(parse_json(debugContext_debugData_logOnlySecurityData_s).behaviors)).["New Device"] == "POSITIVE"
  | project TimeGenerated, actor_alternateId_s, actor_displayName_s, client_userAgent_os_s, client_userAgent_browser_s, client_device_s, client_userAgent_rawUserAgent_s, client_ipAddress_s, client_geographicalContext_country_s, client_geographicalContext_city_s
  | sort by TimeGenerated
```

**2: Okta Administrator logs in during non-business hours**
```
Okta_CL
  | where eventType_s == "user.session.access_admin_app"
  | where outcome_result_s == "SUCCESS"
  | where hourofday(TimeGenerated) !between (5 .. 19)
  | project TimeGenerated, actor_alternateId_s, actor_displayName_s, client_userAgent_os_s, client_userAgent_browser_s, client_device_s, client_userAgent_rawUserAgent_s, client_ipAddress_s, client_geographicalContext_country_s, client_geographicalContext_city_s
  | sort by TimeGenerated
```

**3. Okta user successfully logs in from a new country AND a new geo-location AND a new device**
```
Okta_CL
  | where eventType_s == "user.session.start"
  | where outcome_result_s == "SUCCESS"
  | where parse_json(tostring(parse_json(debugContext_debugData_logOnlySecurityData_s).behaviors)).["New Country"] == "POSITIVE"
  | where parse_json(tostring(parse_json(debugContext_debugData_logOnlySecurityData_s).behaviors)).["New Geo-Location"] == "POSITIVE"
  | where parse_json(tostring(parse_json(debugContext_debugData_logOnlySecurityData_s).behaviors)).["New Device"] == "POSITIVE"
  | project TimeGenerated, actor_alternateId_s, actor_displayName_s, client_userAgent_os_s, client_userAgent_browser_s, client_device_s, client_userAgent_rawUserAgent_s, client_ipAddress_s, client_geographicalContext_country_s, client_geographicalContext_city_s
  | sort by TimeGenerated
```

**4. Okta user successfully logs in from an IP flagged by Emerging Threats or Abuse.ch Threat Intelligence sources**
```
let malicious_ips = (externaldata(possibly_malicous_ip:string)
  [
  @"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
  @"https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
  @"https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
  @"https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt"
  ]
  with(format="txt")
  | where possibly_malicous_ip matches regex "(^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
  | distinct possibly_malicous_ip
  );
  Okta_CL
  | where eventType_s == "user.authentication.sso"
  | where outcome_result_s == "SUCCESS"
  | where isnotempty(client_ipAddress_s)
  | where client_ipAddress_s in (malicious_ips)
  | sort by TimeGenerated
```

**5. Okta user successfully logs in from a Tor exit node**
```
let malicious_ips = (externaldata(possibly_malicous_ip:string)
  [
  @"https://github.com/SecOps-Institute/Tor-IP-Addresses/blob/master/tor-nodes.lst",
  @"https://github.com/SecOps-Institute/Tor-IP-Addresses/blob/master/tor-exit-nodes.lst"
  ]
  with(format="txt")
  | where possibly_malicous_ip matches regex "(^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
  | distinct possibly_malicous_ip
  );
  Okta_CL
  | where eventType_s == "user.authentication.sso"
  | where outcome_result_s == "SUCCESS"
  | where isnotempty(client_ipAddress_s)
  | where client_ipAddress_s in (malicious_ips)
  | sort by TimeGenerated
```

**6. Okta user changed their MFA method or password from a different country**
```
Okta_CL
  | where eventType_s == "user.mfa.factor.activate" and outcome_reason_s == "User set up OKTA_VERIFY_PUSH factor" and outcome_result_s == "SUCCESS"
  | where isnotempty(client_geographicalContext_country_s)
  | join kind = leftanti(
    Okta_CL
    | where eventType_s == "user.mfa.factor.update" and outcome_result_s == "SUCCESS" or eventType_s == "user.account.update_password" and outcome_result_s == "SUCCESS" or eventType_s == "user.account.reset_password" and outcome_result_s == "SUCCESS"    | where isnotempty(client_geographicalContext_country_s)
  ) on client_geographicalContext_country_s
  | project-rename country_of_okta_activation = client_geographicalContext_country_s
  | project TimeGenerated, country_of_okta_activation, eventType_s, actor_alternateId_s, actor_id_s
  | sort by TimeGenerated
```

**7. Okta Global administrator successfully logs in**
```
Okta_CL
  | where actor_alternateId_s == "globaladmin@cryptsus.com" or actor_id_s == "deadBEEF1337admin"
  | where eventType_s == "user.session.start"
  | where outcome_result_s == "SUCCESS"
  | project TimeGenerated, actor_alternateId_s, client_userAgent_os_s, client_userAgent_browser_s, client_ipAddress_s, client_geographicalContext_country_s, client_geographicalContext_city_s, securityContext_domain_s
```

**8. Okta password spray attacks on your Okta tenant**
```
Okta_CL
  | where debugContext_debugData_threatDetections_s contains "Password Spray" or debugContext_debugData_threatDetections_s contains "Brute Force" or debugContext_debugData_threatDetections_s contains \xe2\x80\x9cOkta Brute Force"
    and severity_s == "WARN" or severity_s == "ERROR"
    and debugContext_debugData_threatSuspected_s == "true"
  | sort by TimeGenerated
```

**9. Okta API token created**
```
Okta_CL
  | where eventType_s == "system.api_token.create"
  | where outcome_result_s == "SUCCESS"
  | project TimeGenerated, actor_displayName_s, securityContext_isp_s
  | sort by TimeGenerated
```

**10. Okta user attempts to access unauthorised application(s)**
```
let threshold = 0;
  Okta_CL
  | where isnotempty(actor_alternateId_s)
  | where eventType_s == "app.generic.unauth_app_access_attempt"
  | extend parse_json(target_s)[0].displayName
  | summarize count() by TimeGenerated, actor_alternateId_s, actor_displayName_s, actor_id_s, client_userAgent_os_s,client_geographicalContext_country_s, tostring(target_s_0_displayName)
  | project-rename Okta_application = target_s_0_displayName
  | where count_ > threshold
  | sort by TimeGenerated
```

**11. More than two MFA push notifications got rejected by the Okta user**
```
let threshold = 1;
  Okta_CL
  | where isnotempty(actor_alternateId_s)
  | where eventType_s == "user.mfa.okta_verify.deny_push"
  | summarize count() by  actor_alternateId_s, actor_displayName_s, actor_id_s, client_geographicalContext_country_s
  | where count_ > threshold
```

**12. Okta policy change occurred**
```
Okta_CL
  | where eventType_s == "policy.rule.update" or eventType_s == "policy.lifecycle.update" or eventType_s == "policy.rule.create" or eventType_s == "policy.lifecycle.create"  or eventType_s == "policy.rule.delete" or eventType_s == "policy.lifecycle.delete" or eventType_s == "policy.rule.deactivate" or eventType_s == "policy.lifecycle.deactivate" or eventType_s == "policy.rule.modify" or eventType_s == "policy.lifecycle.modify" or eventType_s == "policy.rule.invalidate" or eventType_s == "policy.lifecycle.invalidate" or eventType_s == "policy.rule.activate" or eventType_s == "policy.lifecycle.activate" or eventType_s == "policy.rule.add" or eventType_s == "policy.lifecycle.add" or eventType_s == "policy.lifecycle.override" or eventType_s ==
"policy.rule.add" or eventType_s == "policy.lifecycle.override" or eventType_s == "network_zone.rule.disabled" or eventType_s == "zone.activate" or eventType_s == "zone.create" or eventType_s == "zone.deactivate" or eventType_s == "zone.delete" or eventType_s == "zone.update" or eventType_s == "application.policy.sign_on.rule.create" or eventType_s == "application.policy.sign_on.rule.delete" or eventType_s == "application.policy.sign_on.rule.delete" or eventType_s == "security.authenticator.lifecycle.deactivate" or eventType_s == "user.mfa.factor.reset_all" or eventType_s == "system.mfa.factor.deactivate" or eventType_s == "security.authenticator.lifecycle.deactivate"
  | where outcome_result_s == "SUCCESS"
  | project TimeGenerated, actor_displayName_s, displayMessage_s, parse_json(target_s)[0].displayName, parse_json(target_s)[1].displayName
  | sort by TimeGenerated
```

**13. More than 5 applications connections got deleted within Okta**
```
let threshold = 4;
  Okta_CL
  | where isnotempty(actor_alternateId_s)
  | where eventType_s == "application.lifecycle.delete"
  | extend parse_json(target_s)[0].displayName
  | summarize count() by actor_alternateId_s, client_userAgent_os_s,client_geographicalContext_country_s
  | where count_ > threshold
```

**14. Okta users is not authenticating with the Okta MFA mobile app**
```
Okta_CL
  | where eventType_s == "system.sms.send_factor_verify_message" or eventType_s == "system.email.send_factor_verify_message" or eventType_s == "system.voice.send_mfa_challenge_call" and eventType_s != "system.push.send_factor_verify_push"
  | where outcome_result_s == "SUCCESS"
  | project TimeGenerated, displayMessage_s, actor_displayName_s, debugContext_debugData_phoneNumber_s, client_userAgent_os_s, client_userAgent_browser_s, client_ipAddress_s, client_geographicalContext_country_s, client_geographicalContext_city_s
  | sort by TimeGenerated, actor_displayName_s
```

**15. More than 10 failed Okta login attempts**
```
let threshold = 9;
  Okta_CL
  | where isnotempty(actor_alternateId_s)
  | where eventType_s == "user.session.start"
  | where outcome_result_s == "FAILURE"
  | summarize count() by  actor_alternateId_s, actor_displayName_s, actor_id_s, client_geographicalContext_country_s
  | where count_ > threshold
```

**16. Okta admin role assigned**
```
Okta_CL
  | where eventType_s == "user.account.privilege.grant" or eventType_s == "group.privilege.grant"
  | where outcome_result_s  == "SUCCESS"
  | project TimeGenerated, debugContext_debugData_privilegeGranted_s, actor_alternateId_s, client_userAgent_os_s, client_userAgent_browser_s, client_geographicalContext_country_s, client_geographicalContext_city_s, client_ipAddress_s, parse_json(target_s)[0].alternateId
```

**17: Okta suspicious activity reported**
```
Okta_CL
  | where eventType_s == "user.account.report_suspicious_activity_by_enduser" or eventType_s == "user.session.impersonation.initiate" or eventType_s == "user.session.impersonation.grant" or eventType_s == "user.mfa.attempt_bypass" or eventType_s == "user.mfa.factor.suspend" or eventType_s == "user.account.update_primary_email"
  | sort by TimeGenerated
```

**18: Okta impossible impossible travel anomaly within 1 hour**
```
let threshold = 1;
  Okta_CL
  | where TimeGenerated > ago(1h)
  | where eventType_s == "user.session.start"
  | where outcome_result_s == "SUCCESS"
  | where isnotempty(client_geographicalContext_country_s)
  | summarize count() by actor_id_s, actor_displayName_s, client_geographicalContext_country_s
  | project-away actor_id_s
  | where count_ > threshold
```

**19: Okta user logs in with a possibly bad user-agent**
```
let malicious_user_agents = (externaldata(possibly_malicous_user_agents:string)
  [
  @"https://raw.githubusercontent.com/repo/to/bad-user_agents.txt"
  ]
  with(format="txt")
  | distinct possibly_malicous_user_agents
  );
  Okta_CL
  | where eventType_s == "user.session.start"
  | where outcome_result_s == "SUCCESS"
  | where client_userAgent_rawUserAgent_s in (malicious_user_agents)
  | project TimeGenerated, client_userAgent_rawUserAgent_s, actor_displayName_s
  | sort by TimeGenerated
```

**20. Locked out Okta users**
```
Okta_CL
  | where eventType_s == "user.account.lock"
  | project TimeGenerated, displayMessage_s, actor_displayName_s, actor_alternateId_s, client_userAgent_os_s, client_device_s, client_geographicalContext_country_s, outcome_reason_s
  | sort by TimeGenerated
```

**And the Okta user got unlocked**
```
Okta_CL
  | where eventType_s == "system.email.mfa_reset_notification.sent_message"
  | extend parse_json(target_s)[0].displayName
  | project TimeGenerated, target_s_0_displayName, actor_alternateId_s, client_userAgent_os_s,client_geographicalContext_country_s, client_geographicalContext_city_s
  | project-rename Unlocked_Okta_user = target_s_0_displayName
  | project-rename Okta_admin_unlock_user = actor_alternateId_s
  | project-rename Okta_admin_user_agent = client_userAgent_os_s
  | project-rename Okta_admin_country = client_geographicalContext_country_s
  | project-rename Okta_admin_city = client_geographicalContext_city_s
```

# License
Berkeley Software Distribution (BSD)

# Author
[Jeroen van Kessel](https://twitter.com/jeroenvkessel) | [cryptsus.com](https://cryptsus.com) - we craft cyber security solutions
