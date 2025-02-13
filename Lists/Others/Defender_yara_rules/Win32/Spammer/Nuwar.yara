rule Spammer_Win32_Nuwar_D_2147595779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Nuwar.D"
        threat_id = "2147595779"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b fe 83 c9 ff 33 c0 33 d2 f2 ae f7 d1 49 74 15 80 04 32}  //weight: 6, accuracy: High
        $x_3_2 = "usbgg5bmm" ascii //weight: 3
        $x_3_3 = "0bempbe/qiq" ascii //weight: 3
        $x_3_4 = "iuuq;00" ascii //weight: 3
        $x_4_5 = {83 c4 38 89 c3 89 f0 25 ff 00 00 00 83 c0 1d}  //weight: 4, accuracy: High
        $x_4_6 = "netsh firewall set allowedprogram '" ascii //weight: 4
        $x_3_7 = {2f 63 6a 7b 00 75 79}  //weight: 3, accuracy: High
        $x_2_8 = "/qiq" ascii //weight: 2
        $x_2_9 = "/cj{" ascii //weight: 2
        $x_2_10 = "cntr.php" ascii //weight: 2
        $x_2_11 = "svcp.csv" ascii //weight: 2
        $x_2_12 = "tibs." ascii //weight: 2
        $x_2_13 = "proxy." ascii //weight: 2
        $x_2_14 = {89 d8 25 ff 00 00 00 83 c0 17 88 85}  //weight: 2, accuracy: High
        $x_2_15 = {ff ff 89 da c1 ea 08 88 95}  //weight: 2, accuracy: High
        $x_2_16 = "notoutpost" ascii //weight: 2
        $x_3_17 = ".php?adv=" ascii //weight: 3
        $x_3_18 = "?adv=%u" ascii //weight: 3
        $x_3_19 = "&code1=%c%c%c%c" ascii //weight: 3
        $x_3_20 = "&table=adv%u" ascii //weight: 3
        $x_3_21 = "/adload.php" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 9 of ($x_2_*))) or
            ((2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((7 of ($x_3_*))) or
            ((1 of ($x_4_*) and 8 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 6 of ($x_3_*))) or
            ((2 of ($x_4_*) and 6 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_6_*) and 7 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 5 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Nuwar_C_2147595780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Nuwar.C"
        threat_id = "2147595780"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows update Service" ascii //weight: 1
        $x_1_2 = "/cntr/bin/" ascii //weight: 1
        $x_1_3 = "/ab.php|http://" ascii //weight: 1
        $x_1_4 = "/cl/main.php" ascii //weight: 1
        $x_1_5 = "/rule.php|http://" ascii //weight: 1
        $x_1_6 = "rivihbugPhSeDen" ascii //weight: 1
        $x_2_7 = "if not exist %s goto done1" ascii //weight: 2
        $x_1_8 = "getblock~!%s" ascii //weight: 1
        $x_3_9 = "%s?name=%s_%s&b=%s&w=%s&" ascii //weight: 3
        $x_1_10 = "%s?gcu=1&%i" ascii //weight: 1
        $x_3_11 = "%s?fstt=1&b=%s&w=%s&name=%s&" ascii //weight: 3
        $x_1_12 = "ab.php" ascii //weight: 1
        $x_1_13 = "mailbody %s" ascii //weight: 1
        $x_1_14 = "taskdir~.exe" ascii //weight: 1
        $x_1_15 = "POST %s HTTP/1.0" ascii //weight: 1
        $x_1_16 = "MAIL FROM: <%s>" ascii //weight: 1
        $x_1_17 = "User-Agent: Mozilla/3.0b5a" ascii //weight: 1
        $x_2_18 = "_galapoper" ascii //weight: 2
        $x_2_19 = {40 6d 61 69 6c 2e 72 75 00 46 72 6f 6d 3a 20 00}  //weight: 2, accuracy: High
        $x_2_20 = {75 70 64 61 74 65 2e 62 61 74 00 6c 6f 67 2e 74 78 74}  //weight: 2, accuracy: High
        $x_2_21 = {72 65 73 7e 21 25 73 00 6d 61 69 6c 62 6f 64 79}  //weight: 2, accuracy: High
        $x_2_22 = {64 6f 77 6e 6c 6f 61 64 20 00 25 73 3f 6e 61 6d}  //weight: 2, accuracy: High
        $x_3_23 = {52 50 3e 81 3e 2e 74 65 78 74 44 3e 81 3e 43 4f 44 45 74 3b 3e 81 3e 2e 64 61 74}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Nuwar_A_2147595781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Nuwar.A!dll"
        threat_id = "2147595781"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 6f 52 6b 00 68 4d 69 63 72}  //weight: 1, accuracy: High
        $x_3_2 = "hlegehrivihbugPhSeDe" ascii //weight: 3
        $x_3_3 = "taskdir;adir;" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Nuwar_B_2147595782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Nuwar.B"
        threat_id = "2147595782"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 38 31 2e 31 37 37 2e 32 36 2e 32 30 2f 61 79 61 79 61 79 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 25 73 22 20 65 6e 61 62 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 6d 74 70 53 65 72 76 65 72 3a 3a 77 6f 72 6b 65 72 2c 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 69 73 20 63 6c 6f 73 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Nuwar_A_2147595784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Nuwar.A"
        threat_id = "2147595784"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {75 07 41 80 3c 08 00 75 e8 80 39 00 74 13 ff 45 08 8b 4d 08 8a 11 40 84 d2 75 d0}  //weight: 2, accuracy: High
        $x_2_2 = "netsh firewall set allowedprogram \"%s" ascii //weight: 2
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_4 = {73 79 73 69 6e 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = "221 Closing connection. Good bye." ascii //weight: 1
        $x_1_6 = "550 Relay Denied" ascii //weight: 1
        $x_1_7 = "rcpt to" ascii //weight: 1
        $x_1_8 = "250 Sender ok" ascii //weight: 1
        $x_1_9 = "mail from" ascii //weight: 1
        $x_1_10 = "250 Hello, pleased to meet you" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

