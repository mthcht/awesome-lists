rule Backdoor_Win32_Silasilsap_STE_2147778825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Silasilsap.STE"
        threat_id = "2147778825"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Silasilsap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VncStartServer" ascii //weight: 1
        $x_1_2 = "VncStopServer" ascii //weight: 1
        $x_1_3 = "bot_shell >" ascii //weight: 1
        $x_1_4 = "BOT-%s(%s)_%S-%S%u%u" ascii //weight: 1
        $x_1_5 = "USR-%s(%s)_%S-%S%u%u" ascii //weight: 1
        $x_1_6 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3a 00 [0-16] 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 73 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_7 = {70 61 73 73 77 6f 72 64 3a [0-16] 63 6f 6d 6d 61 6e 64 73 3a}  //weight: 1, accuracy: Low
        $x_1_8 = "ActiveDll: Dll inject thread" ascii //weight: 1
        $x_1_9 = "*.neverseenthisfile" ascii //weight: 1
        $x_1_10 = "block_input / unblock_input" ascii //weight: 1
        $x_1_11 = "/name Microsoft.PowerOptions" ascii //weight: 1
        $x_1_12 = "PsSup: ShellExecute" ascii //weight: 1
        $x_1_13 = "MOZ_DISABLE_CONTENT_SANDBOX" ascii //weight: 1
        $x_1_14 = "windows.immersiveshell.serviceprovider.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Backdoor_Win32_Silasilsap_STE_2147778826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Silasilsap.STE!!Silasilsap.STE"
        threat_id = "2147778826"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Silasilsap"
        severity = "Critical"
        info = "Silasilsap: an internal category used to refer to some threats"
        info = "STE: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VncStartServer" ascii //weight: 1
        $x_1_2 = "VncStopServer" ascii //weight: 1
        $x_1_3 = "bot_shell >" ascii //weight: 1
        $x_1_4 = "BOT-%s(%s)_%S-%S%u%u" ascii //weight: 1
        $x_1_5 = "USR-%s(%s)_%S-%S%u%u" ascii //weight: 1
        $x_1_6 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3a 00 [0-16] 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 73 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_7 = {70 61 73 73 77 6f 72 64 3a [0-16] 63 6f 6d 6d 61 6e 64 73 3a}  //weight: 1, accuracy: Low
        $x_1_8 = "ActiveDll: Dll inject thread" ascii //weight: 1
        $x_1_9 = "*.neverseenthisfile" ascii //weight: 1
        $x_1_10 = "block_input / unblock_input" ascii //weight: 1
        $x_1_11 = "/name Microsoft.PowerOptions" ascii //weight: 1
        $x_1_12 = "PsSup: ShellExecute" ascii //weight: 1
        $x_1_13 = "MOZ_DISABLE_CONTENT_SANDBOX" ascii //weight: 1
        $x_1_14 = "windows.immersiveshell.serviceprovider.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

