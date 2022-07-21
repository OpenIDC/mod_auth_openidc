
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip{

    param([string]$File, [string]$Destination)

	Write-Host "Unzipping $File to $Destination";
    [System.IO.Compression.ZipFile]::ExtractToDirectory($File, $Destination)
}

function download($URL, $Destination){

	if(!(Test-Path $Destination)){
		Write-Host "Downloading $File to $Destination";
		(New-Object Net.WebClient).DownloadFile($URL,$Destination);
		
		$lNewName = " $((Get-Item $Destination ).DirectoryName)\$((Get-Item $Destination ).Basename)"
		unzip -File $Destination -Destination "$lNewName"
	}else{
		Write-Host "Already downloaded $aFile";
	}
}

$targetFolder = "$((Get-Item -Path ".\").FullName)\target"

if(!(Test-Path $targetFolder)){
	Write-Host "Createing folder $targetFolder";
	mkdir target;
}else{
	Write-Host "Folder $targetFolder already exists"
}

download -URL 'https://www.apachelounge.com/download/VS16/binaries/httpd-2.4.54-win64-VS16.zip' -Destination "$PSScriptRoot\target\httpd-2.4.54-win64-VS16.zip"


