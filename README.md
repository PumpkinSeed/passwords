# passwords

CLI password management system with strong encryption

## Install

```
go get github.com/PumpkinSeed/passwords
go install github.com/PumpkinSeed/passwords
```

### Create environment variable for file

It helps to reduce the necessary flags

```
export PASS_FILE="/path/to/file/secure"
```

## Usage

Generate a new password for key `facebook` and copy it to clipboard

```
passwords generate -key facebook -passphrase s3cur3pw
```

Generate a new password for key `facebook` and copy it to clipboard also print to the propmt

```
passwords generate -key facebook -passphrase s3cur3pw -insecure
```
If the key already exists it's ask for overwrite

--

Get the password from the secure file for key `facebook` and copy it to clipboard

```
passwords get -key facebook -passphrase s3cur3pw
```

Get the password from the secure file for key `facebook` and copy it to clipboard also print to the prompt

```
passwords get -key facebook -passphrase s3cur3pw -insecure
```
--

List the existed keys with the last update date

```
passwords list -passphrase s3cur3pw
```