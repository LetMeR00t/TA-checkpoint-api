set version=1.1.13
set file=TA-checkpoint-api
set spl_file=%file%-%version%.spl
set file_version_underscored=%file%_%version:.=_%

cd C:\Users\tekal\Downloads\
rmdir /s /q extracted
mkdir extracted
cd extracted
xcopy "C:\Users\tekal\Downloads\%spl_file%" "." /Y /I 
tar -x -f %spl_file%

cd C:\Users\tekal\Github\%file%
xcopy "C:\Users\tekal\Downloads\%file_version_underscored%_export.tgz" "appbuilder_%file_version_underscored%_export.tgz*" /Y 
xcopy "C:\Users\tekal\Downloads\%spl_file%" "%spl_file%*" /Y 
rmdir /s /q %file%
mkdir %file%
cd %file%
robocopy "C:\Users\tekal\Downloads\extracted\%file%/" "." /S /E
cd ..
git status
