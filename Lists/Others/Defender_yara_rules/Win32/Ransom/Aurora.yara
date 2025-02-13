rule Ransom_Win32_Aurora_PI_2147741540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Aurora.PI"
        threat_id = "2147741540"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Aurora"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\system\\@@_SILINEN_VERILER_@@.txt" wide //weight: 2
        $x_2_2 = "\\SYSTEM32\\drivers\\gmreadme.txt" wide //weight: 2
        $x_2_3 = "istrator\\Application Data\\000000000.key" wide //weight: 2
        $x_2_4 = "$$$$$$$$$$$$$$$$$$$$$$$$> CRYPTO LOCKER <$$$$$$$$$$$$$$$$$$$$$$$$" ascii //weight: 2
        $x_1_5 = "@@_BENI_OKU_@@.txt" ascii //weight: 1
        $x_1_6 = "@@_DIKKAT_@@.txt" ascii //weight: 1
        $x_2_7 = "\\Release\\Ransom.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Aurora_SIB_2147780092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Aurora.SIB!MTB"
        threat_id = "2147780092"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Aurora"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {3a 52 65 70 65 61 74 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 72 6d 64 69 72 20 22 25 73 22 0d 0a 64 65 6c 20 22 25 73 22}  //weight: 5, accuracy: High
        $x_5_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 5
        $x_5_3 = "\\Boot\\" ascii //weight: 5
        $x_5_4 = "\\BOOTSECT" ascii //weight: 5
        $x_5_5 = "\\pagefile" ascii //weight: 5
        $x_5_6 = "\\System Volume Information\\" ascii //weight: 5
        $x_5_7 = "bootmgr" ascii //weight: 5
        $x_5_8 = "\\Recovery" ascii //weight: 5
        $x_5_9 = "\\Microsoft" ascii //weight: 5
        $x_1_10 = "Every byte on any types of your devices was encrypted" ascii //weight: 1
        $x_1_11 = "Don't try to use backups because it were encrypted too" ascii //weight: 1
        $x_1_12 = "To get all your data back contact us" ascii //weight: 1
        $x_1_13 = "onionmail.org" ascii //weight: 1
        $x_1_14 = "protonmail.com" ascii //weight: 1
        $x_1_15 = "downloaded files from your servers" ascii //weight: 1
        $x_1_16 = "will sell them on the darknet" ascii //weight: 1
        $x_1_17 = "pysa" ascii //weight: 1
        $x_1_18 = ".onion/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_5_*) and 7 of ($x_1_*))) or
            ((8 of ($x_5_*) and 2 of ($x_1_*))) or
            ((9 of ($x_5_*))) or
            (all of ($x*))
        )
}

