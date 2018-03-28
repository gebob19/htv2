import RoomTheme from './RoomTheme';

export default class ClassicRoomTheme implements RoomTheme {
  public paintBackground(canvas: HTMLCanvasElement, ctx: CanvasRenderingContext2D) {
    // White Background
    ctx.fillStyle = 'white';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Black Stars
    let seed = 1;
    function random() {
      var x = Math.sin(seed++) * 10000;
      return x - Math.floor(x);
    }
    
    ctx.fillStyle = 'black';
    Array.from(Array(Math.floor(canvas.width * canvas.height * 0.00125)))
      .map(() => [
        Math.floor(random() * canvas.width),
        Math.floor(random() * canvas.height),
        Math.ceil(random() * 3)
      ])
      .forEach(([ x, y, size ]) => {
        ctx.fillRect(x, y, size, size);
      })
  }

  paintTile(canvas: HTMLCanvasElement, ctx: CanvasRenderingContext2D, x: number, y: number, tileSize: number) {
    ctx.fillStyle = 'black';
    ctx.fillRect(x, y, tileSize, tileSize);
  }

  paintReward(canvas: HTMLCanvasElement, ctx: CanvasRenderingContext2D, x: number, y: number, tileSize: number) {
    ctx.fillStyle = 'red';
    ctx.fillRect(
      x,
      y,
      tileSize,
      tileSize
    );
  }

  paintPlayerPiece(canvas: HTMLCanvasElement, ctx: CanvasRenderingContext2D, x: number, y: number, tileSize: number, skin: string) {
    if (skin[0] === '_') {
      ctx.fillStyle = skin.substr(1);
    } else {
      ctx.fillStyle = 'magenta';
    }
    ctx.fillRect(
      x,
      y,
      tileSize,
      tileSize
    );
  }
}