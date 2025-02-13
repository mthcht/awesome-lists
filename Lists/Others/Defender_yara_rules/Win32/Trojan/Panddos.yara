rule Trojan_Win32_Panddos_B_2147602285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Panddos.B"
        threat_id = "2147602285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Panddos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 49 4e 5f 32 30 30 33 [0-15] 64 72 65 61 6d 32 66 6c 79}  //weight: 1, accuracy: Low
        $x_1_2 = {64 65 78 20 52 65 61 64 43 6c 69 65 6e 74 43 66 67 20 2e 2e 00 52 65 76 65 72 73 65 53 68 65 6c 6c 20 73 74 61 72 74 2e 2e 00 00 00 00 42 69 6e 64 53 68 65 6c 6c 20 6c 65 61 76 65}  //weight: 1, accuracy: High
        $x_1_3 = "welcome to smartdoor cmd shell." ascii //weight: 1
        $x_1_4 = "Login success!Now, you have a system cmd shell^_^A ZA,A ZA,A ZA!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Panddos_C_2147630344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Panddos.C"
        threat_id = "2147630344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Panddos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 53 65 72 76 65 72 5c 44 44 4f 53 ?? ?? ?? 54 68 72 65 61 64 2e 63 70 70}  //weight: 1, accuracy: Low
        $x_1_2 = "HookKeyBoard.dll" ascii //weight: 1
        $x_1_3 = "\\Common\\inc\\HI_PLAY_AudioIN.cpp" ascii //weight: 1
        $x_1_4 = "CreateDDOSSocket Failed." ascii //weight: 1
        $x_1_5 = {73 74 6f 70 20 73 68 61 72 65 64 61 63 63 65 73 73 [0-10] 73 74 61 72 74 20 73 68 61 72 65 64 61 63 63 65 73 73}  //weight: 1, accuracy: Low
        $x_1_6 = "GET ^&&%$%$^%$#^&**(*((&*^%$##$%^&*(*&^%$%^&*.htm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

