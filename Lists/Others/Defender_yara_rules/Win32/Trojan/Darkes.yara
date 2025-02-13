rule Trojan_Win32_Darkes_A_2147643131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Darkes.A"
        threat_id = "2147643131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 63 68 6f 20 5b 41 75 74 6f 52 75 6e 5d 20 3e 20 25 25 ?? 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: Low
        $x_1_2 = "echo start \"\" %0>>%SystemDrive%\\AUTOEXEC.BAT" ascii //weight: 1
        $x_1_3 = "FOR /F \"tokens=1,* delims=: \" %%j in (InfList_exe.txt) do copy /y %0 \"%%j:%%k\"" ascii //weight: 1
        $x_1_4 = "\\Policies\\System /v DisableTaskMgr /t REG_SZ /d 1 /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

