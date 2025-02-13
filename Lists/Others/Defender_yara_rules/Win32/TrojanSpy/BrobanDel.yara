rule TrojanSpy_Win32_BrobanDel_A_2147690445_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BrobanDel.A"
        threat_id = "2147690445"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bananamotonopros" ascii //weight: 1
        $x_1_2 = {4a 00 75 00 6e 00 6b 00 [0-16] 4c 00 69 00 78 00 6f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {70 00 72 00 6f 00 78 00 78 00 35 00 [0-16] 66 00 69 00 72 00 65 00 66 00 6f 00 78 00}  //weight: 1, accuracy: Low
        $x_1_4 = "http://91.108.68.202/up.php" wide //weight: 1
        $x_1_5 = ".globo.com/login/" wide //weight: 1
        $x_1_6 = "people.live.com/export?canary=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_BrobanDel_A_2147690445_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BrobanDel.A"
        threat_id = "2147690445"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\x42\\x52\\x41\\x44\\x45\\x53\\x43\\x4F\\x20\\x46\\x49\\x53\\x49\\x43\\x41" ascii //weight: 1
        $x_1_2 = "\\x53\\x41\\x4E\\x54\\x41\\x4E\\x44\\x45\\x52" ascii //weight: 1
        $x_1_3 = "\\x2E\\x63\\x6F\\x6D\\x2E\\x62\\x72" ascii //weight: 1
        $x_1_4 = "\\x76\\x61\\x6C\\x69\\x64\\x61\\x74\\x65\\x42\\x69\\x6C\\x6C\\x65\\x74" ascii //weight: 1
        $x_1_5 = "\\x5B\\x6E\\x61\\x6D\\x65\\x3D\\x27\\x70\\x61\\x73\\x73\\x77\\x64\\x27\\x5D" ascii //weight: 1
        $x_1_6 = {76 61 72 20 5f 30 78 ?? ?? (30|31|32|33|34|35|36|37|38|39|61|62|63|64|65|66) (30|31|32|33|34|35|36|37|38|39|61|62|63|64|65|66) 3d 5b 22 5c 78}  //weight: 1, accuracy: Low
        $x_1_7 = "()+parseInt(_0x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_Win32_BrobanDel_A_2147690445_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BrobanDel.A"
        threat_id = "2147690445"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\CURRENTVERSION\\RUN" wide //weight: 1
        $x_1_2 = {75 00 73 00 65 00 72 00 66 00 69 00 6c 00 65 00 [0-16] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2f 00 [0-16] 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4a 00 75 00 6e 00 6b 00 [0-16] 4c 00 69 00 78 00 6f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 69 00 67 00 6e 00 20 00 69 00 6e 00 [0-16] 65 00 6e 00 74 00 72 00 61 00 72 00 [0-16] 6f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_5 = {65 00 6e 00 74 00 72 00 61 00 72 00 [0-16] 73 00 69 00 67 00 6e 00 20 00 69 00 6e 00 [0-16] 6f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_6 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 [0-16] 77 00 77 00 77 00 2e 00 68 00 6f 00 74 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_7 = {66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00 [0-16] 69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_BrobanDel_B_2147694821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BrobanDel.B"
        threat_id = "2147694821"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 6f 6a 65 63 74 31 00 00 00 00 46 6f 72 6d 31 00 00 00 46 6f 72 6d 33 00 00 00 46 6f 72 6d 35 00 00 00 46 6f 72 6d 37 [0-255] 46 6f 72 6d 35 33 [0-255] 46 6f 72 6d 31 30 31 [0-4] 46 6f 72 6d 31 30 33}  //weight: 1, accuracy: Low
        $x_1_2 = "dmFyIF8weG" ascii //weight: 1
        $x_1_3 = "XHg3M1x4NzNceDZDXHgyRFx4NzBceDcyXHg2Rlx4NzhceDc5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

