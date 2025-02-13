rule Trojan_Win64_Meralifea_A_2147728404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meralifea.A"
        threat_id = "2147728404"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 85 c0 48 8b f0 0f 84 ?? ?? 00 00 44 8b 84 24 ?? ?? 00 00 48 8b 8c 24 ?? ?? 00 00 4c 8d 8c 24 ?? ?? 00 00 48 8b d0 48 89 5c 24 ?? ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? 00 00 66 81 3e 4d 5a}  //weight: 1, accuracy: Low
        $x_1_2 = {48 81 f9 fe ca 00 00 75 ?? 48 8b 44 24 28 48 85 c0 74 ?? 48 8d 0d ?? ?? ?? ?? 48 89 08 33 c0 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 28 10 00 00 00 48 89 6c 24 20 ff 15 ?? ?? ?? ?? f7 d8 1b c0 25 10 ff ed dc 05 cd cd cd cd}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f9 8e 4e 0e ec 75 10 41 0f b7 00 8b 0c 83 49 03 cb 48 89 4e 08 eb 16 81 f9 aa fc 0d 7c 75 0e}  //weight: 1, accuracy: High
        $x_1_5 = "\\REGISTRY\\Machine\\SYSTEM\\service\\iaStor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Meralifea_A_2147728404_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meralifea.A"
        threat_id = "2147728404"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bd 44 64 6b 20}  //weight: 1, accuracy: High
        $x_2_2 = {74 14 66 81 39 4e 45 75 0d 48 63 51 04 48 03 d1 39 02 48 0f 44 c2 c3}  //weight: 2, accuracy: High
        $x_1_3 = {41 b8 4b 41 50 43}  //weight: 1, accuracy: High
        $x_2_4 = {ba 90 00 00 00 33 c9 41 b8 fe ca 00 00 ff 15}  //weight: 2, accuracy: High
        $x_2_5 = {74 1b 41 83 fb 05 75 0a 80 3e e9 74 10 80 3e e8 74 0b 41 03 fb 49 03 f3 83 ff 06 72 ?? 83 ff 06 0f 82 ?? ?? 00 00 48 8b 4b 30 66 81 39 4d 5a}  //weight: 2, accuracy: Low
        $x_2_6 = {74 0a 80 7f 05 cc 0f 85 ?? ?? 00 00 48 8b 4b 30 66 81 39 4d 5a}  //weight: 2, accuracy: Low
        $x_2_7 = {75 0f 80 3f cc 74 15 80 3f 90 74 10 80 3f c3}  //weight: 2, accuracy: High
        $x_1_8 = "\\Systemroot\\system32\\drivers\\%wZ" ascii //weight: 1
        $x_1_9 = "dump_dumpfve.sys" ascii //weight: 1
        $x_1_10 = "\\NPF-{0179AC45-C226-48e3-A205-DCA79C824051}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Meralifea_A_2147728404_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Meralifea.A"
        threat_id = "2147728404"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Meralifea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ba 30 00 22 00 48 89 46 08 44 8b 4c 24 ?? 49 8b 0c 24 48 8d 44 24 ?? 41 83 c1 28 48 89 44 24 ?? 89 7c 24 ?? 48 89 7c 24 ?? ff 15 ?? ?? ?? ?? 3b c7 74 ?? 48 8b 4c 24 68 ff 15 ?? ?? ?? ?? 48 8b 4c 24 60 ba 10 27 00 00 ff 15 ?? ?? ?? ?? 3b c7 75 ?? 48 8b 4c 24 ?? 48 8d 54 24 ?? ff 15 ?? ?? ?? ?? 81 7c 24 ?? dd cc bb aa}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 43 1c 00 00 10 00 ff 15 ?? ?? ?? ?? 3b c5 74 0a 8b 84 24 ?? 00 00 00 89 43 ?? 48 8b 0b 48 89 6c 24 ?? 48 8d 44 24 ?? 48 89 44 24 ?? 48 8d 44 24 ?? 45 33 c9 45 33 c0 ba 5c 40 07 00}  //weight: 2, accuracy: Low
        $x_2_3 = {ba 20 00 22 00 89 7c 24 ?? 48 89 44 24 ?? ff 15 ?? ?? ?? ?? f7 d8 1b c9 23 4c 24 ?? 81 f9 be ba fe ca}  //weight: 2, accuracy: Low
        $x_2_4 = {ba 00 20 49 82 48 8b cb 44 89 6c 24 ?? 48 89 44 24 ?? 89 6c 24 ?? ff 15 ?? ?? ?? ?? 3b c5 74 0c 81 7c 24 ?? 46 55 53 45}  //weight: 2, accuracy: Low
        $x_2_5 = {8b 56 08 44 8b 84 24 ?? ?? 00 00 8b 4b ?? 41 03 d0 48 0f af d1 66 81 bc 24 ?? ?? 00 00 55 aa 75}  //weight: 2, accuracy: Low
        $x_2_6 = {ff 50 08 33 f6 48 3b c6 48 8b d8 74 ?? 8b 50 04 4c 8b 4c 24 ?? 48 8d 0c 52 48 8d 0c 8d 08 00 00 00 49 3b c9 73 ?? 66 81 38 38 9a}  //weight: 2, accuracy: Low
        $x_2_7 = "/arksig.js" ascii //weight: 2
        $x_1_8 = "/bin/i386/dump.bin" ascii //weight: 1
        $x_1_9 = "/bin/i386/kernel.bin" ascii //weight: 1
        $x_1_10 = "/bin/i386/kernel.sig" ascii //weight: 1
        $x_1_11 = "/boot/boot.cfg" ascii //weight: 1
        $x_1_12 = "/boot/kernel" ascii //weight: 1
        $x_1_13 = "/etc/crypto.key" ascii //weight: 1
        $x_1_14 = "/etc/original.dat" ascii //weight: 1
        $x_1_15 = "/setup.img" ascii //weight: 1
        $x_2_16 = "/simplified.patch" ascii //weight: 2
        $x_1_17 = "\\\\.\\UsbgKrnl" ascii //weight: 1
        $x_1_18 = "EFI PART" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

