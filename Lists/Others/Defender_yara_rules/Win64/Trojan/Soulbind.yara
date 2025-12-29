rule Trojan_Win64_Soulbind_GVA_2147960171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Soulbind.GVA!MTB"
        threat_id = "2147960171"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Soulbind"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /v /c Set FfLol=cmd & !FfLol! < Officers.xla" ascii //weight: 1
        $x_2_2 = "sc.exe /?alksjdfhjf834827435" ascii //weight: 2
        $x_1_3 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32 \"%s\"" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_5 = "PendingFileRenameOperations" ascii //weight: 1
        $x_1_6 = "System\\CurrentControlSet\\Control\\Session Manager\\FileRenameOperations" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

