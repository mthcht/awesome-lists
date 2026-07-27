rule HackTool_Win64_Injector_PAHB_2147959939_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Injector.PAHB!MTB"
        threat_id = "2147959939"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\IAmAntimalware.pdb" ascii //weight: 5
        $x_1_2 = "launchProtected" ascii //weight: 1
        $x_1_3 = "certData" ascii //weight: 1
        $x_2_4 = "CertAddCertificateContextToStore" ascii //weight: 2
        $x_1_5 = "sidInfo" ascii //weight: 1
        $x_1_6 = "sourceKeyPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Injector_LRC_2147974596_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Injector.LRC!MTB"
        threat_id = "2147974596"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f b6 04 19 4c 33 c8 4d 0f af c8 48 ff c3 48 3b da 72 ?? 4c 8d 44 24 30 48 8d 54 24 50 49 8b cf}  //weight: 20, accuracy: Low
        $x_1_2 = "[info] Wait for start %s" ascii //weight: 1
        $x_2_3 = "[-] inject code:" ascii //weight: 2
        $x_3_4 = "[-] inject: %ws" ascii //weight: 3
        $x_4_5 = "Andromeda-CS2-Base.exe" ascii //weight: 4
        $x_5_6 = "[error] Inject" ascii //weight: 5
        $x_6_7 = "[success] Injected" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

