rule Trojan_Win32_DelfCrypt_A_2147657763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfCrypt.A"
        threat_id = "2147657763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 c6 04 24 54 c6 44 24 01 42 c6 44 24 02 45 5a}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\Users\\Mohammed\\Desktop\\Li0n Projects\\LiveFreeTeam Crypter\\Compiler\\Unit1.pas" ascii //weight: 1
        $x_1_3 = "Scratchpad synch problem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

