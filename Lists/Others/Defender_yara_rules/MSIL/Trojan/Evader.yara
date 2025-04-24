rule Trojan_MSIL_Evader_PGE_2147939895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Evader.PGE!MTB"
        threat_id = "2147939895"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Evader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gmo ps12exe -ListAvailable -ea SilentlyContinue" ascii //weight: 2
        $x_2_2 = "Install-Module ps12exe -Scope CurrentUser -Force -ea Stop" ascii //weight: 2
        $x_3_3 = "$NextNumber = $Number+1" ascii //weight: 3
        $x_2_4 = "$NextScript = $PSEXEscript.Replace" ascii //weight: 2
        $x_1_5 = "$NextScript | ps12exe -outputFile $PSScriptRoot/$NextNumber.exe *> $null" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

