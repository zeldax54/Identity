#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["Identity/Identity.csproj", "Identity/"]
COPY ["Identity.Bussiness/Identity.Bussiness.csproj", "Identity.Bussiness/"]
COPY ["Identity.Models/Identity.Models.csproj", "Identity.Models/"]
COPY ["Identity.TokenHandler/Identity.TokenHandler.csproj", "Identity.TokenHandler/"]
COPY ["Identity.DataAccess/Identity.DataAccess.csproj", "Identity.DataAccess/"]
RUN dotnet restore "Identity/Identity.csproj"
COPY . .
WORKDIR "/src/Identity"
RUN dotnet build "Identity.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Identity.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Identity.dll"]