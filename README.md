# Instructions for Use
1. Downloand and run the exe file from: 
    * https://github.com/metheos/node-oauth2-gm/releases/download/prerelease-2/GM-MS-TOKENS.exe
      * It will generate "microsoft_tokens.json" in the same folder where you have run GM-MS-TOKENS.exe
2. In Home Assistant (HA), Go to "Settings --> Add-ons --> File Editor --> Configuration", turn off "Enforce Basepath" and restart the add-on
    * NOTE: This assumes that you have already installed the "[File Editor](https://github.com/home-assistant/addons/tree/master/configurator)" add-on
3. In HA, use File Editor and navigate to the directory named 'ssl' under the root path (/ssl)
    * If you cannot see the 'ssl' directory, then you didn't turn off the switch "Enforce Basepath" and restart the add-on as noted in Step #3 above
4. Create a directory named
    * 'vehicle1' under 'ssl' for Vehicle 1
    * 'vehicle2' under 'ssl' for Vehicle 2 etc.
5. Upload the "microsoft_tokens.json" file generated in Step #1 above into the '/ssl/vehicle1' (or '/ssl/vehicle2' etc.) directory
6. Go to the OnStar2MQTT add-on config:
    * In the field "OnStar TOTP Key", enter any value (e.g. 1234567890)
    * In the field 'Token Location', enter /ssl/vehicle1 (or /ssl/vehicle2 etc.)
      * NOTE: Do NOT include any quotes in the directory name in this step
    * Save settings and restart the OnStar2MQTT add-on.
