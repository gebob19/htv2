const Moderator = require('./Moderator');

module.exports = class FreeRoomModerator extends Moderator {

  constructor() {
    super();
  }

  rewardPlayer(player) {
    player.grow();
  }

  /**
   * player1 has collided with a player piece of player2
   * 
   * @param {Player} player1 
   * @param {Player} player2 
   */
  collision(player1, player2) {
    const socket = this.io.sockets.connected[player1.id];
    this.killPlayer(socket);
  }

  /**
   * Adds a new player to the room, by default in the dead state.
   * 
   * @param {socket} socket players socket
   */
  addPlayer(socket) {
    const player = new Player(this.world, socket.id);
    socket.on('setDirection', direction => {
      player.setDirection(direction);
    });

    this.dead_players.set(socket.id, player);

    this.rewards.push(new Reward(this.world));
    this.rewards.push(new Reward(this.world));
  }
  

  /**
   * The player of socket, can now play in the room.
   * 
   * @param {socket} socket players socket
   */
  spawnPlayer(socket) {
    var player = this.dead_players.get(socket.id);
    this.dead_players.delete(socket.id);
  
    this.alive_players.set(socket.id, player);
  }

  /**
   * The player of socket's state is changed to dead and cannot play in the 
   * room.
   * 
   * @param {socket} socket players socket
   */
  killPlayer(socket) {
    socket.emit('death');

    var player = this.alive_players.get(socket.id);
    player.reset();
    this.alive_players.delete(socket.id);
    this.dead_players.set(socket.id, player);
  }
  
  /**
   * Removes a player from the room, along with two rewards.
   * 
   * @param {socket} socket players socket
   */
  removePlayer(socket) {
    this.alive_players.delete(socket.id);
    this.rewards.pop();
    this.rewards.pop();
  }
}
