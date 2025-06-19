using System;

namespace Org.BouncyCastle.Crypto
{
	internal interface IEngineProvider<TEngine>
	{
		TEngine CreateEngine (EngineUsage usage);
	}

    internal interface IParameterizedEngineProvider<TEngine, TParams>
    {
        TEngine CreateEngine(EngineUsage usage, TParams parameters);
    }
}

