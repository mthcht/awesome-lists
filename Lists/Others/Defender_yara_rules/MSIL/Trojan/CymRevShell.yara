rule Trojan_MSIL_CymRevShell_RDA_2147913004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CymRevShell.RDA!MTB"
        threat_id = "2147913004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CymRevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CymulateReverseShell" ascii //weight: 1
        $x_1_2 = "(New-Object System.Net.WebClient).DownloadFile([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String" wide //weight: 1
        $x_1_3 = "Start-Process -FilePath rundll32.exe -ArgumentList \"$env:TEMP\\$<FILE_TO_DOWNLOAD>$,rundll32EntryPoint\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

