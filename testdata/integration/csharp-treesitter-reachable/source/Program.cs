using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace TestApp;

[ApiController]
[Route("[controller]")]
public class DataController : ControllerBase
{
    [HttpPost("deserialize")]
    public IActionResult Deserialize([FromBody] string payload)
    {
        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.Auto
        };
        var obj = JsonConvert.DeserializeObject(payload, settings);
        return Ok(obj);
    }
}
