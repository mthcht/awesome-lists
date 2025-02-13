rule Trojan_Win32_CredentialFlusher_CCJD_2147922439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialFlusher.CCJD!MTB"
        threat_id = "2147922439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialFlusher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SLEEP ( 2000 )" ascii //weight: 1
        $x_5_2 = "RUN ( $EDGEPATHX86 & \" --kiosk \" & $URL )" ascii //weight: 5
        $x_5_3 = "RUN ( $EDGEPATHX64 & \" --kiosk \" & $URL )" ascii //weight: 5
        $x_1_4 = "CHECKFULLSCREEN ( $BROWSERTYPE )" ascii //weight: 1
        $x_1_5 = "MONITORBROWSER ( \"Chrome\" )" ascii //weight: 1
        $x_1_6 = "MONITORBROWSER ( \"Edge\" )" ascii //weight: 1
        $x_1_7 = "HOTKEYSET ( \"{ESC}\" , \"IgnoreKey\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CredentialFlusher_CCJE_2147922440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialFlusher.CCJE!MTB"
        threat_id = "2147922440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialFlusher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SLEEP ( 2000 )" ascii //weight: 1
        $x_5_2 = "$EDGEPATHX86 & \" --kiosk --edge-kiosk-type=fullscreen --no-first-run --disable-popup-blocking" ascii //weight: 5
        $x_5_3 = "$EDGEPATHX64 & \" --kiosk --edge-kiosk-type=fullscreen --no-first-run --disable-popup-blocking" ascii //weight: 5
        $x_1_4 = "WINGETHANDLE ( \"[CLASS:Chrome_WidgetWin_1]\" )" ascii //weight: 1
        $x_1_5 = "HOTKEYSET ( \"{ESC}\" , \"IgnoreKey\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CredentialFlusher_CCJG_2147923542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialFlusher.CCJG!MTB"
        threat_id = "2147923542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialFlusher"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "$FIRSTURL = \"https://youtube.com/account?=https://accounts.google.com/v3/signin/challenge/pwd\"" ascii //weight: 5
        $x_5_2 = {52 00 55 00 4e 00 57 00 41 00 49 00 54 00 20 00 28 00 20 00 22 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 46 00 20 00 2f 00 49 00 4d 00 20 00 [0-15] 2e 00 65 00 78 00 65 00 20 00 2f 00 54 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_3 = {52 55 4e 57 41 49 54 20 28 20 22 74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 [0-15] 2e 65 78 65 20 2f 54 22 20 2c 20 22 22 20 2c 20 40 53 57 5f 48 49 44 45 20 29}  //weight: 5, accuracy: Low
        $x_1_4 = "--start-fullscreen --no-first-run --disable-session-crashed-bubble --disable-infobars" ascii //weight: 1
        $x_1_5 = "--no-default-browser-check --disable-popup-blocking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

