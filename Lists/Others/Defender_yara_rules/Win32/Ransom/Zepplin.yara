rule Ransom_Win32_Zepplin_A_2147754141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zepplin.A!MTB"
        threat_id = "2147754141"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zepplin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hello! All your documents, photos, databases and other important files are ENCRYPTED!" ascii //weight: 1
        $x_1_2 = "To decode the password you have to buy our special decoding tool" ascii //weight: 1
        $x_1_3 = "wbadmin delete catalog -quiet & wbadmin delete systemstatebackup" ascii //weight: 1
        $x_1_4 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_5 = "bcdedit /set {default} bootstatuspolicy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Zepplin_B_2147754142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zepplin.B!MTB"
        threat_id = "2147754142"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zepplin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\\\Please Read Me!!!.hta" ascii //weight: 1
        $x_1_2 = "D:\\\\Please Read Me!!!.hta" ascii //weight: 1
        $x_1_3 = "A:\\\\Please Read Me!!!.hta" ascii //weight: 1
        $x_1_4 = "B:\\\\Please Read Me!!!.hta" ascii //weight: 1
        $x_1_5 = "\\Downloads\\Please Read Me!!!.hta" ascii //weight: 1
        $x_1_6 = "Cipher not initialized" ascii //weight: 1
        $x_1_7 = "\\Beni_Oku!!!.hta" ascii //weight: 1
        $x_1_8 = ".txt;.doc;.docx;.intex;.pdf;.zip;.rar;.onetoc;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

