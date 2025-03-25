PROJECT=IPK-L4-Scanner/IPK-L4-Scanner.csproj
OUTPUT_DIR=bin/

all: clean publish

build:
	dotnet build $(PROJECT) -c Release

run:
	dotnet run --project $(PROJECT)

clean:
	dotnet clean
	rm -rf $(OUTPUT_DIR)

publish:
	dotnet publish -c Release -o .