rule Trojan_Win32_PowerRunner_A_2147808488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowerRunner.A"
        threat_id = "2147808488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerRunner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "projects\\unmanagedpowershell\\powershellrunner\\" ascii //weight: 10
        $x_10_2 = {3c 4d 6f 64 75 6c 65 3e 00 50 6f 77 65 72 53 68 65 6c 6c 52 75 6e 6e 65 72 2e 64 6c 6c 00 50 6f 77 65 72 53 68 65 6c 6c 52 75 6e 6e 65 72 00 43 75 73 74 6f 6d 50 53 48 6f 73 74}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PowerRunner_A_2147808489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowerRunner.A!!PowerRunner.A"
        threat_id = "2147808489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerRunner"
        severity = "Critical"
        info = "PowerRunner: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "projects\\unmanagedpowershell\\powershellrunner\\" ascii //weight: 10
        $x_10_2 = {3c 4d 6f 64 75 6c 65 3e 00 50 6f 77 65 72 53 68 65 6c 6c 52 75 6e 6e 65 72 2e 64 6c 6c 00 50 6f 77 65 72 53 68 65 6c 6c 52 75 6e 6e 65 72 00 43 75 73 74 6f 6d 50 53 48 6f 73 74}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

