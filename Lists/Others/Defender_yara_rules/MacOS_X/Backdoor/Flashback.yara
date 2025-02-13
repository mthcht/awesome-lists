rule Backdoor_MacOS_X_Flashback_A_2147649885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flashback.A"
        threat_id = "2147649885"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flashback"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IOPlatformUUID" ascii //weight: 1
        $x_1_2 = "launchctl setenv DYLD_INSERT_LIBRARIES" ascii //weight: 1
        $x_2_3 = "Snitch/lsd" ascii //weight: 2
        $x_2_4 = "adobesoftwareupdate" ascii //weight: 2
        $x_5_5 = {48 8d 34 cd 00 00 00 00 48 b8 ab aa aa aa aa aa aa aa 48 f7 e6 48 89 d1 48 c1 e9 02 48 8d 04 49 48 01 c0 48 29 c6 48 83 fe 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MacOS_X_Flashback_B_2147650487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flashback.B"
        threat_id = "2147650487"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flashback"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IOPlatformUUID" ascii //weight: 1
        $x_2_2 = {00 c7 04 24 0b 00 00 00 e8 50 2e 00 00 b8 68 58 4d 56 bb 12 f7 6c 3c b9 0a 00 00 00 ba 58 56 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {83 ec 2c c7 44 24 04 b8 73 00 00 8b 45 0c 8b 00 89 04 24 e8 84 45 00 00 89 c3 85 c0}  //weight: 2, accuracy: High
        $x_3_4 = {8b 85 14 fa ff ff c1 e8 02 ba 15 02 4d 21 f7 e2 c1 ea 04 85 d2 75 0f 89 1c 24 e8 4a 38 00 00 31 ff e9 22 04 00 00 8d 7a ff 69 c2 ec 01 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MacOS_X_Flashback_C_2147650677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flashback.C"
        threat_id = "2147650677"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flashback"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "IOPlatformUUID" ascii //weight: 1
        $x_1_2 = {b8 68 58 4d 56 bb 12 f7 6c 3c b9 0a 00 00 00 ba 58 56 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c1 e8 02 ba 15 02 4d 21 f7 e2 c1 ea 04}  //weight: 1, accuracy: High
        $x_1_4 = {01 ce 89 da 89 d8 c1 fa 1f f7 ff 8b 85 38 f9 ff ff 0f b6 04 10 01 c6 89 f0 0f b6 d0}  //weight: 1, accuracy: High
        $x_1_5 = {83 ec 2c c7 44 24 04 ?? ?? 00 00 8b 45 0c 8b 00 89 04 24 e8 ?? ?? 00 00 89 c3 85 c0 75 24}  //weight: 1, accuracy: Low
        $x_2_6 = {44 89 ea 32 14 03 0f be f2 4c 89 e7 e8 ?? ?? 00 00 48 ff c3 49 8b 06 48 3b 58 e8 72 e3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MacOS_X_Flashback_E_2147654559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flashback.E"
        threat_id = "2147654559"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flashback"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IOPlatformUUID" ascii //weight: 1
        $x_1_2 = "update?if=%&fu=%u" ascii //weight: 1
        $x_1_3 = "launchctl load" ascii //weight: 1
        $x_1_4 = "|oldupdate" ascii //weight: 1
        $x_1_5 = "|<g>|" ascii //weight: 1
        $x_1_6 = "sudo -u" ascii //weight: 1
        $x_10_7 = "6649234;8575343" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MacOS_X_Flashback_E_2147654559_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flashback.E"
        threat_id = "2147654559"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flashback"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IOPlatformUUID" ascii //weight: 1
        $x_1_2 = "/click?data=" ascii //weight: 1
        $x_1_3 = "/search?q=" ascii //weight: 1
        $x_1_4 = "GET /url?" ascii //weight: 1
        $x_1_5 = "BIDOK" ascii //weight: 1
        $x_1_6 = "window.googleJavaScriptRedirect=1" ascii //weight: 1
        $x_1_7 = "1234d678;8a654321" ascii //weight: 1
        $x_1_8 = {d0 e3 e4 e6 ee d6 00 d0 f8 ee e7 ed d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_MacOS_X_Flashback_F_2147655165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flashback.F"
        threat_id = "2147655165"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flashback"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s.%s.so" ascii //weight: 1
        $x_1_2 = "%s|%s|%s|%s|%s|%s|%d" ascii //weight: 1
        $x_1_3 = "%s \"%s%s%s\" %s \"%s" ascii //weight: 1
        $x_1_4 = "IOPlatformUUID" ascii //weight: 1
        $x_1_5 = "sysctl.proc_cputype" ascii //weight: 1
        $x_6_6 = "dFd1js" ascii //weight: 6
        $x_6_7 = {f7 d0 21 c2 81 ?? 80 80 80 80 74 ?? 89 ?? c1 e8 10 f7 c2 80 80 00 00 0f 44}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_6_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MacOS_X_Flashback_G_2147655166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flashback.G"
        threat_id = "2147655166"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flashback"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "IOPlatformUUID" ascii //weight: 1
        $x_1_2 = {25 73 7c 25 73 7c 25 73 7c ?? 7c 25 73 7c 25 73 7c 25 64}  //weight: 1, accuracy: Low
        $x_1_3 = "%s \"%s%s%s\" %s \"%s" ascii //weight: 1
        $x_1_4 = "sysctl.proc_cputype" ascii //weight: 1
        $x_1_5 = "system.privilege.admin" ascii //weight: 1
        $x_5_6 = {84 c0 0f 84 ?? 02 00 00 [0-4] 00 [0-3] e8 ?? ?? 00 00 31 db}  //weight: 5, accuracy: Low
        $x_5_7 = {85 c0 0f 85 ?? 02 00 00 [0-2] 83 fb ?? 75 [0-5] f8 a4 69 34}  //weight: 5, accuracy: Low
        $x_5_8 = {f7 d0 21 c2 81 ?? 80 80 80 80 74 ?? 89 ?? c1 e8 10 f7 c2 80 80 00 00 0f 44}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MacOS_X_Flashback_G_2147655769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flashback.G!ldr"
        threat_id = "2147655769"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flashback"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "User-Agent" ascii //weight: 1
        $x_1_2 = "http://%s%s" ascii //weight: 1
        $x_1_3 = "IOService:/" ascii //weight: 1
        $x_1_4 = "IOPlatformUUID" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f [0-2] 2e [0-2] 2e [0-2] 2e [0-2] 2f 73 74 61 74 5f 73 76 63 2f}  //weight: 1, accuracy: Low
        $x_1_6 = {89 c8 ba 08 00 00 00 a8 01 74 [0-2] d1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_X_Flashback_H_2147656047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flashback.H"
        threat_id = "2147656047"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flashback"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "User-Agent" ascii //weight: 1
        $x_1_2 = "http://%s%s" ascii //weight: 1
        $x_1_3 = "IOService:/" ascii //weight: 1
        $x_1_4 = "IOPlatformUUID" ascii //weight: 1
        $x_1_5 = {25 73 2e 25 75 00 25 73 2e 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {89 c8 ba 08 00 00 00 a8 01 74 [0-2] d1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_X_Flashback_E_2147656481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Flashback.E!ldr"
        threat_id = "2147656481"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Flashback"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_ksyms" ascii //weight: 1
        $x_1_2 = {3c 53 75 24 80 ?? 01 61 75 46 80 ?? 02 66 75 40 80 ?? 03 61 75 3a 80 ?? 04 72}  //weight: 1, accuracy: Low
        $x_1_3 = {3c 57 75 24 80 ?? 01 65 75 1e 80 ?? 02 62}  //weight: 1, accuracy: Low
        $x_1_4 = {01 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 31 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

