rule BrowserModifier_Win32_ShieldSoftCby_224262_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ShieldSoftCby"
        threat_id = "224262"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ShieldSoftCby"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Settings\\FFDefSearch.txt" ascii //weight: 1
        $x_1_2 = "&r=7001&geo=US&ptag=YAHOO&affid=yahoo&app=shield" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_ShieldSoftCby_224262_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/ShieldSoftCby"
        threat_id = "224262"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "ShieldSoftCby"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\ShieldSoft\\Settings\\UserChromeSettings.txt" wide //weight: 2
        $x_1_2 = "By modifying this file, I agree that I am doing so only within Firefox itself, using official, user-driven search engine select" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Explorer\\SearchScopes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

