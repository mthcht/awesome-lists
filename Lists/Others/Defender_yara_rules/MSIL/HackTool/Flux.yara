rule HackTool_MSIL_Flux_A_2147956309_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Flux.A!AMTB"
        threat_id = "2147956309"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Flux"
        severity = "High"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "You are running Flux." ascii //weight: 2
        $x_2_2 = "Successfully built client shellcode! Saved to:\\" ascii //weight: 2
        $x_2_3 = "Hello you are being administrated using Flux Continuation" ascii //weight: 2
        $x_2_4 = "Enable keyboard logging" ascii //weight: 2
        $x_1_5 = "LoadCryptoAddresses" ascii //weight: 1
        $x_1_6 = "InjectDecryptionMethod" ascii //weight: 1
        $x_2_7 = "Flux.Server.DiscordRPC" ascii //weight: 2
        $x_1_8 = "set_EnableAntiVM" ascii //weight: 1
        $x_1_9 = "SendClipboardData" ascii //weight: 1
        $x_2_10 = "DoUACBypass" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

