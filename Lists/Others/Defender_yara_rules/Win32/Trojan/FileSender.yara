rule Trojan_Win32_FileSender_B_2147811986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileSender.B"
        threat_id = "2147811986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileSender"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Get-Process | Where-Object {{$_.Path -like $path}} | " ascii //weight: 5
        $x_5_2 = "Stop-Process -Force;[byte[]]$arr = new-object byte[] {1};Set-Content -Path $path -Value $arr;Remove-Item -Path $path;" ascii //weight: 5
        $x_5_3 = "c:\\work\\file_sender\\sender2\\sender2\\bin\\release\\sender2.pdb" ascii //weight: 5
        $x_5_4 = "!sender2.upload+<isConnected>" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

