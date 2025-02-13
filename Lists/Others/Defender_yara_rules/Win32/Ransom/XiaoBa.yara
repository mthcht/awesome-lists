rule Ransom_Win32_XiaoBa_A_2147731383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/XiaoBa.A!MTB"
        threat_id = "2147731383"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "XiaoBa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XiaoBa-Ransomware" ascii //weight: 1
        $x_1_2 = "Unable to decrypt the file because you are debugging this program" ascii //weight: 1
        $x_1_3 = "cmd /c vssadmin delete shadow /all /quiet " ascii //weight: 1
        $x_1_4 = "wmic shadowcopy delete " ascii //weight: 1
        $x_1_5 = "bcdedit /set {default} boostatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_6 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_7 = "wbadmin delete catalog -quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

